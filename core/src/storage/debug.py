from trezorutils import USE_DEBUGLINK, halt

if not (__debug__ or USE_DEBUGLINK):
    halt("Debugging is disabled")

if __debug__ or USE_DEBUGLINK:
    layout_watcher = False

    reset_internal_entropy = bytearray(32)
    reset_internal_entropy[:] = bytes()
