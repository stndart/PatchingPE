fn0 = r"C:\Users\Svyat\Desktop\RE\PatchingPE\anti-debug-dump\thunks_patch.csv"
thunks_patch = pl.read_csv(fn0)


counter = 0

for patch_addr, mem_old, patch in thunks_patch.rows():
    if patch_bytes(patch_addr, mem_old, patch):
        counter += 1

print(f"Patched {counter}/{thunks_patch.shape[0]} thunks")
