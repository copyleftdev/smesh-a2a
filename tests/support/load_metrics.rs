use std::path::Path;

pub fn process_rss_bytes(pid: u32) -> u64 {
    let text = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup")).unwrap();
    let kib = text
        .lines()
        .find_map(|line| {
            line.strip_prefix("Rss:")
                .and_then(|rest| rest.split_ascii_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
        })
        .expect("Rss in smaps_rollup");
    kib.saturating_mul(1024)
}

pub fn process_fd_count(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .count()
}

pub fn sqlite_file_set_bytes(path: &Path) -> u64 {
    ["", "-wal", "-shm"]
        .into_iter()
        .filter_map(|suffix| {
            std::fs::metadata(format!("{}{suffix}", path.display()))
                .ok()
                .map(|metadata| metadata.len())
        })
        .sum()
}

pub fn nearest_rank_percentile(samples: &[u64], percentile: usize) -> u64 {
    assert!(!samples.is_empty());
    assert!((1..=100).contains(&percentile));
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    let rank = percentile
        .saturating_mul(ordered.len())
        .div_ceil(100)
        .saturating_sub(1);
    ordered[rank.min(ordered.len() - 1)]
}
