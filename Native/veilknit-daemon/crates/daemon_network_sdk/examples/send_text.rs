use daemon_network_sdk::{ClientError, NetworkApp, NetworkIdentity};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let recipient: NetworkIdentity = std::env::args()
        .nth(1)
        .ok_or("usage: send_text <recipient identity> <message>")?
        .parse()?;
    let text = std::env::args()
        .nth(2)
        .ok_or("usage: send_text <recipient identity> <message>")?;

    let app = match NetworkApp::builder("example.send-text")
        .display_name("Send Text Example")
        .connect()
        .await
    {
        Ok(app) => app,
        Err(ClientError::AuthorizationRequired(request)) => {
            println!("Approve with: {}", request.approval_command());
            request.wait().await?
        }
        Err(error) => return Err(error.into()),
    };

    let receipt = app.send_text(&recipient, text).await?;
    println!("Queued message {}", receipt.message_id);
    Ok(())
}
