//! Language-agnostic lexical preprocessing.
//!
//! Apps may supply already-separated terms when they know better. Otherwise we
//! use simple human-visible delimiters. Suspiciously long unbroken runs fall
//! back to grapheme n-grams rather than becoming one enormous token.

use std::collections::{BTreeMap, HashMap, HashSet};
use deunicode::deunicode;
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;
use super::types::{
    ScriptClass, ScriptProfile, WordComparisonKeys, WordId, WordSimilarity,
    LEXICAL_ABSOLUTE_LONG_RUN_GRAPHEMES, LEXICAL_CONTEXT_MINHASH_COMPONENTS,
    LEXICAL_LANGUAGE_MINHASH_COMPONENTS, LEXICAL_LONG_RUN_GRAPHEMES,
    LEXICAL_MAX_TERM_BYTES, LEXICAL_WORD_ID_VERSION,
};

#[derive(Debug, Clone)]
pub struct Lexeme { pub canonical: String, pub word_id: WordId, pub script: ScriptProfile, pub comparison: WordComparisonKeys }
#[derive(Debug, Clone, Default)]
pub struct TokenizedText { pub words: Vec<Lexeme>, pub subwords: Vec<Lexeme> }

pub fn canonicalize_word_v1(raw: &str) -> Option<String> {
    let trimmed = raw.trim_matches(is_edge_punctuation);
    if trimmed.is_empty() { return None; }
    let lowered: String = trimmed.chars().flat_map(char::to_lowercase).collect();
    let normalized: String = lowered.nfc().collect();
    let normalized = normalized.trim();
    if normalized.is_empty() || normalized.len() > LEXICAL_MAX_TERM_BYTES { None } else { Some(normalized.to_string()) }
}

pub fn derive_word_id(canonical: &str) -> WordId {
    let mut hasher=blake3::Hasher::new(); hasher.update(b"VK-LEX-WORD-ID-V1\0"); hasher.update(&LEXICAL_WORD_ID_VERSION.to_le_bytes()); hasher.update(canonical.as_bytes()); WordId(*hasher.finalize().as_bytes())
}

pub fn tokenize_text(text: &str, pretokenized: &[String]) -> TokenizedText {
    if !pretokenized.is_empty() {
        return TokenizedText { words: pretokenized.iter().filter_map(|t| lexeme(t)).collect(), subwords: Vec::new() };
    }
    let mut output=TokenizedText::default();
    for raw in text.split(is_simple_delimiter) {
        let Some(canonical)=canonicalize_word_v1(raw) else { continue; };
        let graphemes: Vec<&str>=UnicodeSegmentation::graphemes(canonical.as_str(),true).collect();
        let script=script_profile(&canonical);
        if should_use_subword_fallback(graphemes.len(), &script) {
            for n in [2usize,3usize] {
                if graphemes.len()<n { continue; }
                for start in 0..=(graphemes.len()-n) {
                    let piece=graphemes[start..start+n].concat();
                    output.subwords.push(Lexeme { word_id: derive_subword_id(&piece,n), script: script_profile(&piece), comparison: comparison_keys(&piece), canonical: piece });
                }
            }
            continue;
        }
        if let Some(item)=lexeme(&canonical) { output.words.push(item); }
    }
    output
}

pub fn lexeme(raw:&str)->Option<Lexeme>{ let canonical=canonicalize_word_v1(raw)?; Some(Lexeme{word_id:derive_word_id(&canonical),script:script_profile(&canonical),comparison:comparison_keys(&canonical),canonical}) }
pub fn derive_subword_id(piece:&str,width:usize)->WordId{ let mut h=blake3::Hasher::new();h.update(b"VK-LEX-SUBWORD-V1\0");h.update(&(width as u16).to_le_bytes());h.update(piece.as_bytes());WordId(*h.finalize().as_bytes()) }

fn should_use_subword_fallback(graphemes:usize, profile:&ScriptProfile)->bool{
    if graphemes>LEXICAL_ABSOLUTE_LONG_RUN_GRAPHEMES{return true;} if graphemes<=LEXICAL_LONG_RUN_GRAPHEMES{return false;}
    let non_segmenting=[ScriptClass::Han,ScriptClass::Hiragana,ScriptClass::Katakana,ScriptClass::Thai].into_iter().map(|s|profile.counts.get(&s).copied().unwrap_or(0)).sum::<u32>();
    profile.alphabetic_or_numeric>0 && non_segmenting as f64/profile.alphabetic_or_numeric as f64>=0.5
}
fn is_simple_delimiter(ch:char)->bool{ ch.is_whitespace() || matches!(ch,','|';'|':'|'!'|'?'|'('|')'|'['|']'|'{'|'}'|'<'|'>'|'/'|'\\'|'|'|'"'|'“'|'”'|'‘'|'’'|'\n'|'\r'|'\t') || ch=='.' }
fn is_edge_punctuation(ch:char)->bool{ ch.is_whitespace() || matches!(ch,','|';'|':'|'!'|'?'|'('|')'|'['|']'|'{'|'}'|'<'|'>'|'/'|'\\'|'|'|'"'|'“'|'”'|'‘'|'’'|'.') }

pub fn script_profile(value:&str)->ScriptProfile{
    let mut counts=BTreeMap::new(); let mut alphabetic_or_numeric=0u32; let mut diacritic_characters=0u32; let mut total_characters=0u32;
    for ch in value.chars(){ total_characters=total_characters.saturating_add(1); if ch.is_alphanumeric(){alphabetic_or_numeric=alphabetic_or_numeric.saturating_add(1);*counts.entry(classify_script(ch)).or_insert(0)+=1;} let decomposed:String=ch.to_string().nfd().collect();if decomposed.chars().count()>1||is_combining_mark(ch){diacritic_characters=diacritic_characters.saturating_add(1);} }
    ScriptProfile{counts,alphabetic_or_numeric,diacritic_characters,total_characters}
}
fn classify_script(ch:char)->ScriptClass{match ch as u32{0x0041..=0x024F|0x1E00..=0x1EFF=>ScriptClass::Latin,0x0370..=0x03FF|0x1F00..=0x1FFF=>ScriptClass::Greek,0x0400..=0x052F|0x2DE0..=0x2DFF|0xA640..=0xA69F=>ScriptClass::Cyrillic,0x0590..=0x05FF=>ScriptClass::Hebrew,0x0600..=0x06FF|0x0750..=0x077F|0x08A0..=0x08FF=>ScriptClass::Arabic,0x0900..=0x097F=>ScriptClass::Devanagari,0x3040..=0x309F=>ScriptClass::Hiragana,0x30A0..=0x30FF|0x31F0..=0x31FF=>ScriptClass::Katakana,0x3400..=0x4DBF|0x4E00..=0x9FFF|0xF900..=0xFAFF=>ScriptClass::Han,0xAC00..=0xD7AF|0x1100..=0x11FF|0x3130..=0x318F=>ScriptClass::Hangul,0x0E00..=0x0E7F=>ScriptClass::Thai,_=>ScriptClass::Other}}
fn is_combining_mark(ch:char)->bool{matches!(ch as u32,0x0300..=0x036F|0x1AB0..=0x1AFF|0x1DC0..=0x1DFF|0x20D0..=0x20FF|0xFE20..=0xFE2F)}

pub fn comparison_keys(canonical:&str)->WordComparisonKeys{WordComparisonKeys{accent_fold_hash:digest16(b"VK-LEX-ACCENT-V1\0",accent_fold(canonical).as_bytes()),transliteration_hash:digest16(b"VK-LEX-TRANSLIT-V1\0",transliteration_fold(canonical).as_bytes()),visual_fold_hash:digest16(b"VK-LEX-VISUAL-V1\0",visual_fold(canonical).as_bytes())}}
fn digest16(domain:&[u8],bytes:&[u8])->[u8;16]{let mut h=blake3::Hasher::new();h.update(domain);h.update(bytes);let mut r=[0u8;16];r.copy_from_slice(&h.finalize().as_bytes()[..16]);r}
pub fn accent_fold(value:&str)->String{value.nfd().filter(|&ch|!is_combining_mark(ch)).collect::<String>().nfc().collect()}
pub fn transliteration_fold(value:&str)->String{deunicode(value).to_lowercase()}
pub fn visual_fold(value:&str)->String{let accent=accent_fold(value);let mut r=String::with_capacity(accent.len());for ch in accent.chars(){match ch{'-'|'_'|' '|'.'=>{},'0'=>r.push('o'),'1'=>r.push('i'),'3'=>r.push('e'),'4'=>r.push('a'),'5'=>r.push('s'),'7'=>r.push('t'),_=>r.push(ch)}}r}

pub fn compare_words(left:&str,right:&str)->WordSimilarity{
    let l=canonicalize_word_v1(left).unwrap_or_default();let r=canonicalize_word_v1(right).unwrap_or_default();if l.is_empty()||r.is_empty(){return WordSimilarity{exact:0.0,normalized:0.0,edit:0.0,accent_fold:0.0,transliteration:0.0,visual:0.0,combined:0.0};}
    let exact=(left==right)as u8 as f32;let normalized=(l==r)as u8 as f32;let edit=normalized_edit_similarity(&l,&r);let af=normalized_edit_similarity(&accent_fold(&l),&accent_fold(&r));let tr=normalized_edit_similarity(&transliteration_fold(&l),&transliteration_fold(&r));let vi=normalized_edit_similarity(&visual_fold(&l),&visual_fold(&r));let combined=exact.max(normalized).max(edit*0.92).max(af*0.96).max(tr*0.90).max(vi*0.88).clamp(0.0,1.0);WordSimilarity{exact,normalized,edit,accent_fold:af,transliteration:tr,visual:vi,combined}
}
fn normalized_edit_similarity(left:&str,right:&str)->f32{let l:Vec<char>=left.chars().collect();let r:Vec<char>=right.chars().collect();let m=l.len().max(r.len());if m==0{return 1.0;}let d=damerau_levenshtein(&l,&r);(1.0-d as f32/m as f32).clamp(0.0,1.0)}
fn damerau_levenshtein(left:&[char],right:&[char])->usize{let rows=left.len()+1;let cols=right.len()+1;let mut t=vec![0usize;rows*cols];for i in 0..rows{t[i*cols]=i;}for j in 0..cols{t[j]=j;}for i in 1..rows{for j in 1..cols{let cost=usize::from(left[i-1]!=right[j-1]);let mut v=(t[(i-1)*cols+j]+1).min(t[i*cols+j-1]+1).min(t[(i-1)*cols+j-1]+cost);if i>1&&j>1&&left[i-1]==right[j-2]&&left[i-2]==right[j-1]{v=v.min(t[(i-2)*cols+j-2]+1);}t[i*cols+j]=v;}}t[left.len()*cols+right.len()]}

pub fn minhash_word_ids<'a,I>(ids:I,components:usize)->Vec<u16> where I:IntoIterator<Item=&'a WordId>{let unique:HashSet<WordId>=ids.into_iter().copied().collect();let components=components.clamp(1,128);let mut sig=vec![u16::MAX;components];for word in unique{for(index,slot)in sig.iter_mut().enumerate(){let mut h=blake3::Hasher::new();h.update(b"VK-LEX-MINHASH-V1\0");h.update(&(index as u16).to_le_bytes());h.update(&word.0);let b=h.finalize();let v=u16::from_le_bytes([b.as_bytes()[0],b.as_bytes()[1]]);*slot=(*slot).min(v);}}sig}
pub fn topic_minhash(ids:&[WordId])->Vec<u16>{minhash_word_ids(ids.iter(),LEXICAL_CONTEXT_MINHASH_COMPONENTS)}
pub fn language_minhash(ids:&[WordId],mention_counts:&HashMap<WordId,u16>,common_ids:&HashSet<WordId>)->Vec<u16>{let mut candidates:Vec<WordId>=ids.iter().copied().filter(|id|common_ids.contains(id)||mention_counts.get(id).copied().unwrap_or(0)>1).collect();if candidates.is_empty(){let mut ranked:Vec<(WordId,u16)>=mention_counts.iter().map(|(id,c)|(*id,*c)).collect();ranked.sort_by(|a,b|b.1.cmp(&a.1));candidates.extend(ranked.into_iter().take(8).map(|(id,_)|id));}minhash_word_ids(candidates.iter(),LEXICAL_LANGUAGE_MINHASH_COMPONENTS)}
pub fn minhash_similarity(left:&[u16],right:&[u16])->f32{if left.is_empty()||left.len()!=right.len(){return 0.0;}left.iter().zip(right).filter(|(a,b)|a==b).count()as f32/left.len()as f32}

#[cfg(test)]mod tests{use super::*;#[test]fn normalization_keeps_diacritics(){assert_ne!(derive_word_id("resume"),derive_word_id("résumé"));assert_eq!(compare_words("resume","résumé").accent_fold,1.0);}#[test]fn visual_name_variants(){assert!(compare_words("first-name","firstnam3").combined>0.8);}#[test]fn japanese_run_uses_subwords(){let r=tokenize_text("これはとてもながいぶんしょうでくうはくをつかわずにかかれていますこれはさらにのびます",&[]);assert!(r.words.is_empty());assert!(!r.subwords.is_empty());}}
