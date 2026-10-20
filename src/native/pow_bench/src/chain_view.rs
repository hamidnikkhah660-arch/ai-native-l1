//! Two intentionally different chain-view validators for differential testing.
//! The data model is synthetic and is not production consensus code.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub id: u64,
    pub prev: Option<u64>,
    pub work: u64,
    pub claimed_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainView {
    pub tip: u64,
    pub total_work: u64,
}

fn cumulative_a(headers: &[Header], tip: u64) -> Option<u64> {
    let mut total = 0u64;
    let mut current = tip;

    for _ in 0..headers.len() {
        let header = headers.iter().find(|h| h.id == current)?;
        if !header.claimed_valid {
            return None;
        }
        total = total.checked_add(header.work)?;

        match header.prev {
            Some(prev) => current = prev,
            None => return Some(total),
        }
    }

    None
}

fn cumulative_b(headers: &[Header], tip: u64) -> Option<u64> {
    let mut index = std::collections::HashMap::new();
    for header in headers {
        if index.insert(header.id, header).is_some() {
            return None;
        }
    }

    let mut current = tip;
    let mut visited = std::collections::HashSet::new();
    let mut total = 0u64;

    loop {
        if !visited.insert(current) {
            return None;
        }

        let header = *index.get(&current)?;
        if !header.claimed_valid {
            return None;
        }
        total = total.checked_add(header.work)?;

        match header.prev {
            Some(prev) => current = prev,
            None => return Some(total),
        }
    }
}

pub fn client_a_best(headers: &[Header], tips: &[u64]) -> Option<ChainView> {
    let mut best: Option<ChainView> = None;

    for &tip in tips {
        let Some(total_work) = cumulative_a(headers, tip) else {
            continue;
        };

        let candidate = ChainView { tip, total_work };
        let replace = best
            .as_ref()
            .map(|b| (candidate.total_work, candidate.tip) > (b.total_work, b.tip))
            .unwrap_or(true);
        if replace {
            best = Some(candidate);
        }
    }
    best
}

pub fn client_b_best(headers: &[Header], tips: &[u64]) -> Option<ChainView> {
    let mut best: Option<ChainView> = None;

    for &tip in tips {
        if let Some(total_work) = cumulative_b(headers, tip) {
            match best.as_ref() {
                Some(current) if (current.total_work, current.tip) >= (total_work, tip) => {}
                _ => {
                    best = Some(ChainView { tip, total_work });
                }
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_chain() -> Vec<Header> {
        vec![
            Header {
                id: 0,
                prev: None,
                work: 1,
                claimed_valid: true,
            },
            Header {
                id: 1,
                prev: Some(0),
                work: 5,
                claimed_valid: true,
            },
            Header {
                id: 2,
                prev: Some(1),
                work: 5,
                claimed_valid: true,
            },
            Header {
                id: 3,
                prev: Some(2),
                work: 5,
                claimed_valid: true,
            },
        ]
    }

    #[test]
    fn both_clients_select_same_valid_tip() {
        let headers = base_chain();
        assert_eq!(client_a_best(&headers, &[3]), client_b_best(&headers, &[3]));
        assert_eq!(
            client_a_best(&headers, &[3]),
            Some(ChainView {
                tip: 3,
                total_work: 16
            })
        );
    }

    #[test]
    fn invalid_longer_branch_is_rejected_by_both() {
        let mut headers = base_chain();
        headers.push(Header {
            id: 100,
            prev: Some(3),
            work: 1000,
            claimed_valid: false,
        });

        assert!(client_a_best(&headers, &[100]).is_none());
        assert!(client_b_best(&headers, &[100]).is_none());

        let expected = Some(ChainView {
            tip: 3,
            total_work: 16,
        });
        assert_eq!(client_a_best(&headers, &[3, 100]), expected);
        assert_eq!(client_b_best(&headers, &[3, 100]), expected);
    }

    #[test]
    fn deterministic_tie_break_is_identical() {
        let mut headers = base_chain();
        headers.extend([
            Header {
                id: 10,
                prev: Some(1),
                work: 7,
                claimed_valid: true,
            },
            Header {
                id: 11,
                prev: Some(1),
                work: 7,
                claimed_valid: true,
            },
        ]);

        let a = client_a_best(&headers, &[10, 11]).unwrap();
        let b = client_b_best(&headers, &[10, 11]).unwrap();

        assert_eq!(a, b);
        assert_eq!(a.tip, 11);
        assert_eq!(a.total_work, 13);
    }

    #[test]
    fn malformed_graph_is_not_accepted() {
        let headers = vec![
            Header {
                id: 0,
                prev: None,
                work: 1,
                claimed_valid: true,
            },
            Header {
                id: 1,
                prev: Some(2),
                work: 5,
                claimed_valid: true,
            },
            Header {
                id: 2,
                prev: Some(1),
                work: 5,
                claimed_valid: true,
            },
        ];

        assert!(client_a_best(&headers, &[1]).is_none());
        assert!(client_b_best(&headers, &[1]).is_none());
    }

    #[test]
    fn overflowed_work_is_rejected_consistently() {
        let headers = vec![
            Header {
                id: 0,
                prev: None,
                work: u64::MAX,
                claimed_valid: true,
            },
            Header {
                id: 1,
                prev: Some(0),
                work: 1,
                claimed_valid: true,
            },
        ];

        assert!(client_a_best(&headers, &[1]).is_none());
        assert!(client_b_best(&headers, &[1]).is_none());
    }

    #[test]
    fn order_of_peer_tips_does_not_change_choice() {
        let headers = vec![
            Header {
                id: 0,
                prev: None,
                work: 1,
                claimed_valid: true,
            },
            Header {
                id: 1,
                prev: Some(0),
                work: 5,
                claimed_valid: true,
            },
            Header {
                id: 10,
                prev: Some(1),
                work: 4,
                claimed_valid: true,
            },
            Header {
                id: 11,
                prev: Some(1),
                work: 8,
                claimed_valid: true,
            },
        ];

        let forward_a = client_a_best(&headers, &[10, 11]).unwrap();
        let reverse_a = client_a_best(&headers, &[11, 10]).unwrap();
        let forward_b = client_b_best(&headers, &[10, 11]).unwrap();
        let reverse_b = client_b_best(&headers, &[11, 10]).unwrap();

        assert_eq!(forward_a, reverse_a);
        assert_eq!(forward_b, reverse_b);
        assert_eq!(forward_a, forward_b);
    }

    #[test]
    fn differential_many_fixed_forks() {
        for i in 0..100u64 {
            let fork_a = 1000 + i * 2;
            let fork_b = fork_a + 1;

            let headers = vec![
                Header {
                    id: 0,
                    prev: None,
                    work: 1,
                    claimed_valid: true,
                },
                Header {
                    id: 1,
                    prev: Some(0),
                    work: 5 + (i % 3),
                    claimed_valid: true,
                },
                Header {
                    id: fork_a,
                    prev: Some(1),
                    work: 4 + (i % 5),
                    claimed_valid: true,
                },
                Header {
                    id: fork_b,
                    prev: Some(1),
                    work: 6 + (i % 5),
                    claimed_valid: true,
                },
                Header {
                    id: 9000 + i,
                    prev: Some(fork_a),
                    work: 50,
                    claimed_valid: false,
                },
            ];

            let tips = [fork_a, fork_b, 9000 + i];
            assert_eq!(
                client_a_best(&headers, &tips),
                client_b_best(&headers, &tips),
                "differential mismatch at case {i}"
            );
        }
    }
}
