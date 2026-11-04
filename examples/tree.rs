use std::{path::PathBuf, sync::Arc};

use tree_fucker::{Config, LoadAll, Tree, runtime::TokioRuntime, std_fs::StdFileSystem};

#[tokio::main(flavor = "current_thread")]
async fn main() -> tree_fucker::Result<()> {
    let filesystem = Arc::new(StdFileSystem::new());
    let runtime = Arc::new(TokioRuntime::current());

    let (tree, mut updates) =
        Tree::open(filesystem, PathBuf::from("."), Arc::new(LoadAll), Config::default(), runtime).await?;

    tree.initial_scan_complete().await?;

    let snapshot = tree.snapshot();
    let health = tree.health();
    let stats = tree.stats();

    println!("snapshot: {snapshot:?}");
    println!("health: {health:?}");
    println!("stats: {stats:?}");

    // Stop reconciliation before draining the remaining updates.
    tree.shutdown().await?;
    while let Some(event) = updates.next().await {
        println!("{event:?}");
    }

    Ok(())
}
