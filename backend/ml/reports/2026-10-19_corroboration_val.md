# Classifier threshold and corroboration (val)

- date 2026-10-19; offline pipeline (rules, UPI check, classifier); val 2642 messages (1619 scams, 156 Indian)
- rules alone, val scam recall: 237/1619 (14.6%); examples flagged by rules alone: 24/36
- corroboration on: the classifier alone (no rule outside SUPPORTING_RULES of weight >= 0.3, no UPI evidence) cannot reach 'suspicious'

| threshold | corroboration | val scam recall | val Indian scam recall | val genuine FPR | val promo FPR | examples keeping verdict | polished_dev recall | polished_dev FPR |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 0.5 | off | 1453/1619 (89.7%) | 141/156 (90.4%) | 11/905 (1.2%) | 15/118 (12.7%) | 35/36 | 20/20 (100.0%) | 3/20 (15.0%) |
| 0.5 | on | 312/1619 (19.3%) | 76/156 (48.7%) | 2/905 (0.2%) | 2/118 (1.7%) | 35/36 | 15/20 (75.0%) | 1/20 (5.0%) |
| 0.6 | off | 1453/1619 (89.7%) | 141/156 (90.4%) | 10/905 (1.1%) | 15/118 (12.7%) | 36/36 | 20/20 (100.0%) | 3/20 (15.0%) |
| 0.6 | on | 312/1619 (19.3%) | 76/156 (48.7%) | 1/905 (0.1%) | 2/118 (1.7%) | 36/36 | 15/20 (75.0%) | 1/20 (5.0%) |
| 0.7 | off | 1450/1619 (89.6%) | 141/156 (90.4%) | 9/905 (1.0%) | 15/118 (12.7%) | 36/36 | 20/20 (100.0%) | 2/20 (10.0%) |
| 0.7 | on | 311/1619 (19.2%) | 76/156 (48.7%) | 1/905 (0.1%) | 2/118 (1.7%) | 36/36 | 15/20 (75.0%) | 1/20 (5.0%) |
| 0.8 | off | 1430/1619 (88.3%) | 141/156 (90.4%) | 7/905 (0.8%) | 15/118 (12.7%) | 36/36 | 19/20 (95.0%) | 2/20 (10.0%) |
| 0.8 | on | 311/1619 (19.2%) | 76/156 (48.7%) | 1/905 (0.1%) | 2/118 (1.7%) | 36/36 | 15/20 (75.0%) | 1/20 (5.0%) |
| 0.9 | off | 1356/1619 (83.8%) | 135/156 (86.5%) | 5/905 (0.6%) | 11/118 (9.3%) | 36/36 | 18/20 (90.0%) | 1/20 (5.0%) |
| 0.9 | on | 311/1619 (19.2%) | 76/156 (48.7%) | 1/905 (0.1%) | 1/118 (0.8%) | 36/36 | 15/20 (75.0%) | 1/20 (5.0%) |
| 0.95 | off | 1266/1619 (78.2%) | 127/156 (81.4%) | 4/905 (0.4%) | 9/118 (7.6%) | 36/36 | 18/20 (90.0%) | 1/20 (5.0%) |
| 0.95 | on | 307/1619 (19.0%) | 74/156 (47.4%) | 1/905 (0.1%) | 1/118 (0.8%) | 36/36 | 15/20 (75.0%) | 1/20 (5.0%) |

Scams flagged without corroboration but not with it (val):

- threshold 0.5: 1141 of 1619 scams (65 of 156 Indian)
- threshold 0.6: 1141 of 1619 scams (65 of 156 Indian)
- threshold 0.7: 1139 of 1619 scams (65 of 156 Indian)
- threshold 0.8: 1119 of 1619 scams (65 of 156 Indian)
- threshold 0.9: 1045 of 1619 scams (59 of 156 Indian)
- threshold 0.95: 959 of 1619 scams (53 of 156 Indian)
