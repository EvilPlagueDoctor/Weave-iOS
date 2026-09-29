use daemon_network_sdk::{ClientError, NetworkApp};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = match NetworkApp::builder("example.echo")
        .display_name("Echo Example")
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

    let mut messages = app.subscribe().await?;
    println!("Echo app is listening as {}", app.local_user().identity);
    loop {
        let message = messages.next().await?;
        if message.conversation_id.is_some() {
            app.respond(&message, &message.payload).await?;
        } else {
            app.send(&message.sender, &message.payload).await?;
        }
    }
}
