use insiedr_core::core::ipc::{NamedPipeClient, IPC_PIPE_NAME};
use std::thread;
use std::time::Duration;

fn main() {
    println!("=== InsiEDR User Session Broker (Session 1+ UI Context) ===");
    println!("[Broker] Connecting to Session 0 Service IPC Pipe: {}", IPC_PIPE_NAME);

    loop {
        match NamedPipeClient::connect(IPC_PIPE_NAME) {
            Ok(client) => {
                println!("[Broker] Connected to InsiEDR Service Named Pipe successfully.");
                // Streaming keystroke and UI telemetry to the service
                loop {
                    let heartbeat_msg = b"{\"event\": \"user_session_heartbeat\", \"active\": true}";
                    if client.send_message(heartbeat_msg).is_err() {
                        eprintln!("[Broker] Pipe connection severed. Reconnecting...");
                        break;
                    }
                    thread::sleep(Duration::from_secs(10));
                }
            }
            Err(_) => {
                thread::sleep(Duration::from_secs(5));
            }
        }
    }
}
