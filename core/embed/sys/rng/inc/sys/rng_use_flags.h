

#pragma once

#include <trezor_types.h>

// This module records which real TRNG implementations were used, allowing
// callers to verify that strong random numbers were generated using a TRNG.

/**
 * @brief TRNG types.
 */
typedef enum {
  RNG_TYPE_MCU,
  RNG_TYPE_OPTIGA,
  RNG_TYPE_TROPIC,
} rng_type_t;

/**
 * @brief Clears all RNG flags.
 *
 * This function resets the internal state of the RNG flags, indicating that no
 * RNG types have been used or set.
 */
void rng_use_flags_clear(void);

#ifndef TREZOR_EMULATOR
/**
 * @brief Marks the specified RNG type as used.
 *
 * @note This function is intentionally unavailable in emulator builds. Code
 * using a PRNG must not call it; it may only be called by real TRNG
 * implementations in hardware builds.
 */
void rng_use_flag_set(rng_type_t type);
#endif

/**
 * @brief Reads the use flagstate of the specified RNG type.
 *
 * @return true if the specified RNG type has been used
 */
bool rng_use_flag_is_set(rng_type_t type);
