use std::collections::{BTreeMap, HashMap};
use serde::{Deserialize, Serialize};
use super::sketches::{DeterministicSample, HllSketch, MentionStatistics};

pub const LEXICAL_MODULE_VERSION:u16=1;
pub const LEXICAL_WORD_ID_VERSION:u16=1;
pub const LEXICAL_CANONICALIZATION_VERSION:u16=1;
pub const LEXICAL_PHRASE_ID_VERSION:u16=1;
pub const LEXICAL_LIBRARY_RECORD_VERSION:u16=1;
pub const LEXICAL_ADVERTISEMENT_RECORD_VERSION:u16=1;
pub const LEXICAL_DEFAULT_LIBRARY_NAME:&str="default";
pub const LEXICAL_DEFAULT_LAYER:&str="content";
pub const LEXICAL_EPOCH_SECS:u64=24*60*60;
pub const LEXICAL_ACTIVE_WINDOW_DAYS:u16=7;
pub const LEXICAL_DAILY_EPOCHS_TO_KEEP:u16=14;
pub const LEXICAL_MAX_LOCAL_LIBRARIES:usize=32;
pub const LEXICAL_MAX_WORDS_IN_MEMORY:usize=2048;
pub const LEXICAL_MAX_WORDS_DURABLE:usize=256;
pub const LEXICAL_MAX_NEIGHBORS_PER_DIRECTION:usize=32;
pub const LEXICAL_MAX_SAMPLE_POINTS:usize=32;
pub const LEXICAL_MAX_MINHASH_EXEMPLARS:usize=8;
pub const LEXICAL_CONTEXT_MINHASH_COMPONENTS:usize=32;
pub const LEXICAL_LANGUAGE_MINHASH_COMPONENTS:usize=32;
pub const LEXICAL_ASSOCIATION_RADIUS:usize=3;
pub const LEXICAL_LONG_RUN_GRAPHEMES:usize=24;
pub const LEXICAL_ABSOLUTE_LONG_RUN_GRAPHEMES:usize=64;
pub const LEXICAL_MAX_TERM_BYTES:usize=256;
pub const LEXICAL_MAX_LAYER_BYTES:usize=64;
pub const LEXICAL_MAX_LIBRARY_NAME_BYTES:usize=64;
pub const LEXICAL_MAX_FIELD_ID_BYTES:usize=96;
pub const LEXICAL_MAX_OBJECT_ID_BYTES:usize=256;
pub const LEXICAL_MAX_TEXT_BYTES:usize=256*1024;
pub const LEXICAL_MAX_PRETOKENIZED_TERMS:usize=8192;
pub const LEXICAL_MAX_SEARCH_TERMS:usize=16;
pub const LEXICAL_MAX_CANDIDATE_HINTS:usize=64;
pub const LEXICAL_PHRASE_MIN_DISTINCT_OBJECTS:f64=5.0;
pub const LEXICAL_PHRASE_MIN_CONDITIONAL:f64=0.55;
pub const LEXICAL_GOSSIP_TTL_SECS:u64=30*60;
pub const LEXICAL_GOSSIP_MAX_NEIGHBORS:usize=6;
pub const LEXICAL_BACKGROUND_TICK_SECS:u64=30;
pub const LEXICAL_DHT_FLUSH_SECS:u64=5*60;
pub const LEXICAL_GOSSIP_DIRTY_WORDS_PER_TICK:usize=24;
pub const LEXICAL_GOSSIP_DIRTY_PHRASES_PER_TICK:usize=12;
pub const LEXICAL_REMOTE_LIBRARY_FANOUT:usize=6;
pub const LEXICAL_REMOTE_READ_CONCURRENCY:usize=4;
pub const LEXICAL_LIBRARY_MANIFEST_SUBKEY:u32=0;
pub const LEXICAL_LIBRARY_PAGE_START:u32=1;
pub const LEXICAL_LIBRARY_PAGE_SUBKEYS:u32=63;
pub const LEXICAL_LIBRARY_TOTAL_SUBKEYS:u16=64;
pub const LEXICAL_LIBRARY_MAX_PAGE_BYTES:usize=15*1024;
pub const LEXICAL_MEMBERSHIP_FILTER_BYTES:usize=32;
pub const LEXICAL_GOSSIP_NAMESPACE_WORD:&str="_veilknit.lexical.word.v1";
pub const LEXICAL_GOSSIP_NAMESPACE_PHRASE:&str="_veilknit.lexical.phrase.v1";
pub const LEXICAL_GOSSIP_NAMESPACE_POSTING:&str="_veilknit.lexical.posting.v1";
// Reuse the existing gossip diagnostic app id so the daemon test surface can
// use already-verified topology without requiring a separately installed app.
pub const LEXICAL_TEST_APPLICATION_ID:&str="veilknit.daemon.gossip-index-test.v1";
pub const LEXICAL_TEST_LIBRARY_NAME:&str="test";
pub const LEXICAL_TEST_LAYER:&str="profile";

#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq,Hash,PartialOrd,Ord)]pub struct WordId(pub [u8;32]);
impl WordId{pub fn hex(&self)->String{hex::encode(self.0)}pub fn short_hex(&self)->String{hex::encode(&self.0[..8])}}
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq,Hash,PartialOrd,Ord)]pub struct LibraryId(pub [u8;16]);impl LibraryId{pub fn hex(&self)->String{hex::encode(self.0)}}
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq,Hash,PartialOrd,Ord)]pub struct PhraseId(pub [u8;32]);impl PhraseId{pub fn hex(&self)->String{hex::encode(self.0)}}

#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq,Hash,PartialOrd,Ord)]pub enum ScriptClass{Latin,Cyrillic,Greek,Arabic,Hebrew,Devanagari,Han,Hiragana,Katakana,Hangul,Thai,Other}
#[derive(Debug,Clone,Serialize,Deserialize,Default,PartialEq,Eq)]pub struct ScriptProfile{pub counts:BTreeMap<ScriptClass,u32>,pub alphabetic_or_numeric:u32,pub diacritic_characters:u32,pub total_characters:u32}
impl ScriptProfile{pub fn dominant_script(&self)->Option<ScriptClass>{self.counts.iter().max_by_key(|(_,c)|*c).map(|(s,_)|*s)}pub fn dominant_fraction(&self)->f64{let Some((_,c))=self.counts.iter().max_by_key(|(_,c)|*c)else{return 0.0;};if self.alphabetic_or_numeric==0{0.0}else{*c as f64/self.alphabetic_or_numeric as f64}}}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct WordComparisonKeys{pub accent_fold_hash:[u8;16],pub transliteration_hash:[u8;16],pub visual_fold_hash:[u8;16]}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]pub struct WordSimilarity{pub exact:f32,pub normalized:f32,pub edit:f32,pub accent_fold:f32,pub transliteration:f32,pub visual:f32,pub combined:f32}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct EpochEvidence{pub epoch:u64,pub distinct_objects:HllSketch,pub distinct_occurrences:HllSketch}
impl EpochEvidence{pub fn new(epoch:u64)->Self{Self{epoch,distinct_objects:HllSketch::word(),distinct_occurrences:HllSketch::word()}}pub fn merge(&mut self,other:&Self){let _=self.distinct_objects.merge(&other.distinct_objects);let _=self.distinct_occurrences.merge(&other.distinct_occurrences);}}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct LayerEvidence{pub layer:String,pub daily:BTreeMap<u64,EpochEvidence>,pub sample:DeterministicSample}
impl LayerEvidence{pub fn new(layer:String)->Self{Self{layer,daily:BTreeMap::new(),sample:DeterministicSample::with_capacity(LEXICAL_MAX_SAMPLE_POINTS)}}}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct NeighborEpochEvidence{pub epoch:u64,pub distance_occurrences:Vec<HllSketch>,pub distinct_objects:HllSketch}
impl NeighborEpochEvidence{pub fn new(epoch:u64)->Self{Self{epoch,distance_occurrences:(0..LEXICAL_ASSOCIATION_RADIUS).map(|_|HllSketch::tiny()).collect(),distinct_objects:HllSketch::tiny()}}pub fn merge(&mut self,other:&Self){for(a,b)in self.distance_occurrences.iter_mut().zip(&other.distance_occurrences){let _=a.merge(b);}let _=self.distinct_objects.merge(&other.distinct_objects);}}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct NeighborEvidence{pub word_id:WordId,pub daily:BTreeMap<u64,NeighborEpochEvidence>,pub last_seen_epoch:u64}
impl NeighborEvidence{pub fn new(word_id:WordId)->Self{Self{word_id,daily:BTreeMap::new(),last_seen_epoch:0}}pub fn merge(&mut self,other:&Self){for(epoch,src)in &other.daily{let dst=self.daily.entry(*epoch).or_insert_with(||NeighborEpochEvidence::new(*epoch));dst.merge(src);}self.last_seen_epoch=self.last_seen_epoch.max(other.last_seen_epoch);}pub fn estimated_distinct_objects_all(&self)->f64{super::sketches::union_hll(4,self.daily.values().map(|e|&e.distinct_objects)).estimate()}pub fn estimated_occurrences_at(&self,distance:usize,minimum_epoch:u64,current_epoch:u64)->f64{super::sketches::union_hll(4,self.daily.range(minimum_epoch..=current_epoch).filter_map(|(_,e)|e.distance_occurrences.get(distance.saturating_sub(1)))).estimate()}}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct PhraseEvidence{pub phrase_id:PhraseId,pub layer:String,pub components:Vec<WordId>,pub daily:BTreeMap<u64,EpochEvidence>,pub left_occurrences:BTreeMap<u64,HllSketch>,pub promoted:bool,pub last_seen_epoch:u64,pub revision:u64}
impl PhraseEvidence{pub fn new(phrase_id:PhraseId,layer:String,components:Vec<WordId>,epoch:u64)->Self{Self{phrase_id,layer,components,daily:BTreeMap::new(),left_occurrences:BTreeMap::new(),promoted:false,last_seen_epoch:epoch,revision:1}}}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct LexicalWordEntry{pub word_id:WordId,pub word_id_version:u16,pub canonicalization_version:u16,pub script:ScriptProfile,pub comparison:WordComparisonKeys,pub layers:BTreeMap<String,LayerEvidence>,pub previous:Vec<NeighborEvidence>,pub following:Vec<NeighborEvidence>,#[serde(default)]pub context_exemplars:Vec<Vec<u16>>,#[serde(default)]pub language_exemplars:Vec<Vec<u16>>,pub first_seen_epoch:u64,pub last_seen_epoch:u64,pub revision:u64}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct UniverseLayerEvidence{pub layer:String,pub daily:BTreeMap<u64,HllSketch>}
impl UniverseLayerEvidence{pub fn new(layer:String)->Self{Self{layer,daily:BTreeMap::new()}}}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct LexicalLibraryManifest{pub record_version:u16,pub library_id:LibraryId,pub application_id:String,pub library_name:String,pub generation:u64,pub updated_at:u64,pub current_epoch:u64,pub epoch_secs:u64,pub active_window_days:u16,pub word_count:u32,pub phrase_count:u32,pub populated_pages:Vec<u16>,pub node_coordinate:[u8;32],pub retention_radius:[u8;32],pub membership_filter:[u8;LEXICAL_MEMBERSHIP_FILTER_BYTES],#[serde(default)]pub universe_layers:Vec<UniverseLayerEvidence>}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct LexicalLibraryPage{pub record_version:u16,pub library_id:LibraryId,pub generation:u64,pub page:u16,pub words:Vec<LexicalWordEntry>,#[serde(default)]pub phrases:Vec<PhraseEvidence>}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct LexicalLibraryAdvertisement{pub library_id:LibraryId,pub application_id:String,pub library_name:String,pub library_dht:String,pub generation:u64,pub updated_at:u64,pub word_count:u32,pub current_epoch:u64,pub active_window_days:u16,pub node_coordinate:[u8;32],pub retention_radius:[u8;32],pub membership_filter:[u8;LEXICAL_MEMBERSHIP_FILTER_BYTES]}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct LexicalLibraryAdvertisementSet{pub record_version:u16,pub updated_at:u64,pub libraries:Vec<LexicalLibraryAdvertisement>}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]pub struct LexicalWordStats{pub window_days:u16,pub estimated_universe_objects:f64,pub estimated_objects_containing_word:f64,pub prevalence:f64,pub rarity_idf:f64,pub rarity_normalized:f64,pub specificity:f64,pub evidence_confidence:f64,pub search_utility:f64,pub mention_statistics:MentionStatistics}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]pub struct LexicalNeighborStat{pub word_id:WordId,pub direction:String,pub distance:u8,pub estimated_occurrences:f64,pub estimated_distinct_objects:f64,pub conditional_probability:f64,pub confidence:f64}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]pub struct LexicalWordView{pub word_id:WordId,pub layer:String,pub stats:LexicalWordStats,pub script:ScriptProfile,pub neighbors:Vec<LexicalNeighborStat>,pub context_exemplars:Vec<Vec<u16>>,pub language_exemplars:Vec<Vec<u16>>,pub sources_consulted:usize}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct LexicalCandidateHint{pub object_id:String,pub generation:u64,pub origin_main_dht:String,pub authoritative_pointer:Option<String>,pub matched_words:usize,pub verification:String}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]pub struct LexicalSearchResult{pub library_id:LibraryId,pub terms:Vec<WordId>,pub words:Vec<LexicalWordView>,pub candidates:Vec<LexicalCandidateHint>,pub gossip_peers_contacted:usize,pub dht_libraries_consulted:usize}
#[derive(Debug,Clone)]pub struct LexicalObserveRequest{pub library_name:String,pub layer:String,pub object_id:String,pub generation:u64,pub field_id:String,pub text:Option<String>,pub pretokenized_terms:Vec<String>,pub authoritative_pointer:Option<String>,pub publish_posting_hint:bool}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]pub struct LexicalObserveResult{pub library_id:LibraryId,pub words_observed:usize,pub unique_words:usize,pub subword_tokens:usize,pub associations_observed:usize,pub phrases_considered:usize,pub topic_minhash:Vec<u16>,pub language_minhash:Vec<u16>,pub current_epoch:u64}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]pub struct LexicalLibraryStats{pub application_id:String,pub library_name:String,pub library_id:LibraryId,pub library_dht:String,pub generation:u64,pub word_count:usize,pub phrase_count:usize,pub dirty_pages:usize,pub dirty_gossip_words:usize,pub dirty_phrases:usize,pub current_epoch:u64}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]pub struct AssociationMetrics{pub left:WordId,pub right:WordId,pub layer:String,pub window_days:u16,pub estimated_joint_objects:f64,pub conditional_right_given_left:f64,pub pmi:Option<f64>,pub confidence:f64}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct LexicalGossipNeighbor{pub word_id:WordId,pub direction:u8,pub distance:u8,pub occurrence_sketch:HllSketch,pub object_sketch:HllSketch}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct LexicalGossipWordSummary{pub version:u16,pub library_id:LibraryId,pub layer:String,pub word_id:WordId,pub epoch:u64,pub distinct_objects:HllSketch,pub distinct_occurrences:HllSketch,pub neighbors:Vec<LexicalGossipNeighbor>,pub script:ScriptProfile,#[serde(default)]pub context_exemplar:Vec<u16>,#[serde(default)]pub language_exemplar:Vec<u16>}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct LexicalGossipPhraseSummary{pub version:u16,pub library_id:LibraryId,pub layer:String,pub phrase_id:PhraseId,pub components:Vec<WordId>,pub epoch:u64,pub distinct_objects:HllSketch,pub distinct_occurrences:HllSketch,pub left_occurrences:HllSketch}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]pub struct StoredLibraryDescriptor{pub application_id:String,pub library_name:String,pub library_id:LibraryId,pub package_index:usize}
#[derive(Debug,Clone,Serialize,Deserialize,Default)]pub struct StoredLexicalManagerState{pub version:u16,pub libraries:Vec<StoredLibraryDescriptor>}
#[derive(Debug,Clone,Default)]pub struct ObjectProfileAccumulator{pub generation:u64,pub fields:HashMap<String,Vec<WordId>>,pub field_layers:HashMap<String,String>}
