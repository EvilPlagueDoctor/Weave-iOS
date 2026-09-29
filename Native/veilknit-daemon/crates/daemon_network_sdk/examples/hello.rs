use daemon_network_sdk::{ClientError, NetworkApp};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = match NetworkApp::builder("example.hello")
        .display_name("Hello Network")
        .connect()
        .await
    {
        Ok(app) => app,
        Err(ClientError::AuthorizationRequired(request)) => {
            println!("Approve this app in the daemon with:");
            println!("  {}", request.approval_command());
            request.wait().await?
        }
        Err(error) => return Err(error.into()),
    };

    println!("Daemon user: {}", app.local_user().username);
    println!("Network identity: {}", app.local_user().identity);
    Ok(())
}
