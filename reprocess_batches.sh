#!/bin/bash

for batch in batch_1_baseline batch_2_mixed batch_3_mixed batch_4_mixed batch_5_mixed
do
    echo "Processing $batch..."
    python3 rule_engine.py attack_batches/$batch
    python3 ml_predict.py attack_batches/$batch
    echo "$batch done!"
done

echo "All batches reprocessed!"
