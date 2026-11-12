# Dispatch fuzzing corpus

Regenerated evidence for the structured Ethernet -> IP -> transport fuzzing
harness in `dpkt/dispatch_fuzz.py`. Recreate the files with:

```sh
python -m dpkt.dispatch_fuzz
```

The run is deterministic (fixed seed, see `dispatch_fuzz.DEFAULT_SEED`).

- `original_sample.bin` - the single-layer mutation that the reference parser
  rejects but the deliberately relaxed `RelaxedTCP` parser accepts.
- `minimised_sample.bin` - the delta-debugged reduction of the original. The
  shrinker only keeps candidates that still instantiate the target layer, so
  this can never degrade into an empty packet that misses the layer.
- `evidence.json` - the fixed seed, mutation id, recorded layer chains,
  raw-byte fallback flags, exception types and the proof that both samples
  reach the same target layer (`TCP`).
