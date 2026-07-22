# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Enable C language for VDF lzcnt.c compilation
enable_language(C)

include(AddWindowsResources)

configure_file(${PROJECT_SOURCE_DIR}/cmake/bitcoin-build-config.h.in bitcoin-build-config.h USE_SOURCE_PERMISSIONS @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

#=============================
# Subprojects
#=============================
# Subprojects include subdirectories that do or could have tests
# and/or benchmark binaries, such as all subtrees and univalue.
# These need to be included before CMAKE_*_OUTPUT_DIRECTORY variables
# are set, so output locations of subproject tests and libraries are
# not overridden.
include(../cmake/crc32c.cmake)
include(../cmake/leveldb.cmake)
include(../cmake/minisketch.cmake)
include(../cmake/blst.cmake)
find_package(OpenSSL REQUIRED)

# For Windows static builds, OpenSSL (libcrypto) needs these system libraries.
# We append them to OpenSSL::Crypto's INTERFACE_LINK_LIBRARIES so they follow
# libcrypto.a in link order (static linking is order-dependent).
if(WIN32)
  set_property(TARGET OpenSSL::Crypto APPEND PROPERTY
    INTERFACE_LINK_LIBRARIES ws2_32 crypt32 wldap32
  )
endif()

# libargon2 — backs the vendored v3 admission-puzzle verification
# (verification/pow_v3.cpp, TIP-0003). pow_v3.cpp is written to
# degrade gracefully: argon2id_digest() is compiled only under
# POW_V3_HAVE_ARGON2 and otherwise throws at runtime, so a binary can build
# without libargon2 and simply cannot verify a v3 admission nonce until it is
# rebuilt with it. That matters only after v3 activation; test images and the
# release toolchain install libargon2 so verification is fully exercised there.
# The cross/depends desktop toolchains (macOS x86_64, Windows, static Linux)
# have no argon2 package, so detection is best-effort here — a hard requirement
# would break every desktop build for a not-yet-activated feature. libargon2
# provides no CMake package, so detect the header + library directly
# (Debian/Ubuntu: libargon2-dev; Homebrew: argon2).
find_path(ARGON2_INCLUDE_DIR NAMES argon2.h)
find_library(ARGON2_LIBRARY NAMES argon2)
if(ARGON2_INCLUDE_DIR AND ARGON2_LIBRARY)
  add_library(argon2_argon2 UNKNOWN IMPORTED)
  set_target_properties(argon2_argon2 PROPERTIES
    IMPORTED_LOCATION "${ARGON2_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${ARGON2_INCLUDE_DIR}"
  )
  add_library(Argon2::Argon2 ALIAS argon2_argon2)
  # Compiled globally (not per-target) so pow_v3.cpp, its consumers and the unit
  # tests all agree on whether argon2id_digest is available.
  add_compile_definitions(POW_V3_HAVE_ARGON2)
  message(STATUS "libargon2 found: v3 admission verification enabled (${ARGON2_LIBRARY})")
else()
  message(WARNING "libargon2 not found (argon2.h / libargon2): building WITHOUT v3 admission verification. "
                  "argon2id_digest() will throw if called; rebuild with libargon2-dev (or `brew install argon2`) "
                  "before enabling v3. Fine for pre-activation / desktop builds.")
endif()

add_subdirectory(univalue)
if (ENABLE_IPC AND NOT WITH_EXTERNAL_LIBMULTIPROCESS)
  include(../cmake/libmultiprocess.cmake)
  add_libmultiprocess(ipc/libmultiprocess)
endif()
#=============================
# secp256k1 (external)
#=============================
message("")
message("Using external secp256k1 (zkp) library...")

set(_SECP256K1_HINTS
    ${CMAKE_CURRENT_SOURCE_DIR}/external/secp256k1-zkp
    ${CMAKE_CURRENT_SOURCE_DIR}/external/secp256k1-zkp/include
    ${CMAKE_PREFIX_PATH}
    /usr/local/include
    /usr/include
)

find_path(SECP256K1_INCLUDE_DIR
  NAMES secp256k1.h
  PATHS ${_SECP256K1_HINTS}
  PATH_SUFFIXES include
)

find_library(SECP256K1_LIBRARY
  NAMES secp256k1
  PATHS ${CMAKE_PREFIX_PATH} /usr/local/lib /usr/lib
  PATH_SUFFIXES lib lib64
)

if(NOT SECP256K1_INCLUDE_DIR OR NOT SECP256K1_LIBRARY)
  message(FATAL_ERROR "secp256k1-zkp not found. Ensure it is built and installed before configuring bcore.")
endif()

add_library(secp256k1 STATIC IMPORTED)
set_target_properties(secp256k1 PROPERTIES
  IMPORTED_LOCATION "${SECP256K1_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${SECP256K1_INCLUDE_DIR}"
  INTERFACE_COMPILE_DEFINITIONS "SECP256K1_STATIC"
)

# Set top-level target output locations.
if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
endif()
if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
endif()
if(NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
endif()

add_custom_target(generate_build_info
  BYPRODUCTS ${PROJECT_BINARY_DIR}/src/bitcoin-build-info.h
  COMMAND ${CMAKE_COMMAND} -DBUILD_INFO_HEADER_PATH=${PROJECT_BINARY_DIR}/src/bitcoin-build-info.h -DSOURCE_DIR=${PROJECT_SOURCE_DIR} -P ${PROJECT_SOURCE_DIR}/cmake/script/GenerateBuildInfo.cmake
  COMMENT "Generating bitcoin-build-info.h"
  VERBATIM
)
add_library(bitcoin_clientversion STATIC EXCLUDE_FROM_ALL
  clientversion.cpp
)
target_link_libraries(bitcoin_clientversion
  PRIVATE
    core_interface
)
add_dependencies(bitcoin_clientversion generate_build_info)

add_subdirectory(crypto)
add_subdirectory(util)
if(ENABLE_IPC)
  add_subdirectory(ipc)
endif()

add_library(bitcoin_consensus STATIC EXCLUDE_FROM_ALL
  arith_uint256.cpp
  consensus/difficulty_cfd.cpp
  consensus/scalar_cfd.cpp
  consensus/scalar_cfd_leaf.cpp
  consensus/scalar_cfd_snapshot.cpp
  consensus/merkle.cpp
  consensus/tx_check.cpp
  hash.cpp
  primitives/block.cpp
  primitives/proofblob.cpp
  primitives/transaction.cpp
  pubkey.cpp
  script/interpreter.cpp
  script/script.cpp
  script/script_error.cpp
  uint256.cpp
)
target_link_libraries(bitcoin_consensus
  PRIVATE
    core_interface
    secp256k1
  PUBLIC
    bitcoin_crypto
)

if(WITH_ZMQ)
  add_subdirectory(zmq)
endif()

# Home for common functionality shared by different executables and libraries.
# Similar to `bitcoin_util` library, but higher-level.
add_library(bitcoin_common STATIC EXCLUDE_FROM_ALL
  addresstype.cpp
  base58.cpp
  bech32.cpp
  chain.cpp
  chainparams.cpp
  chainparamsbase.cpp
  coins.cpp
  common/args.cpp
  common/bloom.cpp
  common/config.cpp
  common/init.cpp
  common/interfaces.cpp
  common/messages.cpp
  common/netif.cpp
  common/pcp.cpp
  common/run_command.cpp
  common/settings.cpp
  common/signmessage.cpp
  common/system.cpp
  common/url.cpp
  compressor.cpp
  core_read.cpp
  core_write.cpp
  deploymentinfo.cpp
  external_signer.cpp
  assets/asset.cpp
  assets/asset_parser_v1.cpp
  assets/canonical_vk.cpp
  assets/icu_payload.cpp
  assets/icu_acceptance_record.cpp
  assets/kyc_delegation.cpp
  # Pure option-series / difficulty derivation core (no wallet/UTXO state) so the core
  # optionseries.derive/verify RPCs can link it without the wallet library.
  wallet/difficulty_contract.cpp
  wallet/option_series.cpp
  wallet/scalar_note_pair.cpp
  wallet/scalar_cfd_contract.cpp
  init/common.cpp
  kernel/chainparams.cpp
  key.cpp
  key_io.cpp
  mldsakey.cpp
  merkleblock.cpp
  net_permissions.cpp
  net_types.cpp
  netaddress.cpp
  netbase.cpp
  outputtype.cpp
  policy/feerate.cpp
  policy/policy.cpp
  pow.cpp
  protocol.cpp
  psbt.cpp
  node/psbt_mldsa.cpp
  rpc/rawtransaction_util.cpp
  rpc/request.cpp
  rpc/util.cpp
  scheduler.cpp
  script/descriptor.cpp
  script/miniscript.cpp
  script/parsing.cpp
  script/sign.cpp
  script/signingprovider.cpp
  script/solver.cpp
)
target_link_libraries(bitcoin_common
  PRIVATE
    core_interface
    bitcoin_util
    univalue
    secp256k1
    Boost::headers
    Boost::locale
    Boost::thread
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
    $<$<PLATFORM_ID:Windows>:ws2_32>
    ${ZSTD_LIBRARIES}
  PUBLIC
    bitcoin_consensus
)
target_include_directories(bitcoin_common PRIVATE ${ZSTD_INCLUDE_DIRS})

# --- VDF verifier (GMP-based, verification only) ---
# Locate chiavdf root robustly.
set(CHIAVDF_DIR "" CACHE PATH "Path to shared-utils/chiavdf root directory")
if(NOT CHIAVDF_DIR)
  set(_chiavdf_candidates
    ${CMAKE_SOURCE_DIR}/shared-utils/chiavdf
    ${CMAKE_SOURCE_DIR}/../shared-utils/chiavdf
    ${CMAKE_SOURCE_DIR}/../../shared-utils/chiavdf
    ${PROJECT_SOURCE_DIR}/../../shared-utils/chiavdf
    ${PROJECT_SOURCE_DIR}/../shared-utils/chiavdf
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../shared-utils/chiavdf
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../shared-utils/chiavdf
    ${CMAKE_CURRENT_SOURCE_DIR}/external/chiavdf
  )
  foreach(d IN LISTS _chiavdf_candidates)
    if(EXISTS "${d}/src/verifier.h")
      set(CHIAVDF_DIR "${d}" CACHE PATH "Path to shared-utils/chiavdf root directory" FORCE)
      break()
    endif()
  endforeach()
endif()

if(NOT CHIAVDF_DIR)
  message(FATAL_ERROR "chiavdf not found. Set -DCHIAVDF_DIR=/abs/path/to/shared-utils/chiavdf or place it under repo root.")
endif()

set(CHIAVDF_SRC_DIR "${CHIAVDF_DIR}/src")

add_library(bitcoin_vdf STATIC EXCLUDE_FROM_ALL
  vdf/VdfVerify.cpp
  vdf/VdfGenerate.cpp
  ${CHIAVDF_SRC_DIR}/refcode/lzcnt.c
)
target_include_directories(bitcoin_vdf PRIVATE ${CHIAVDF_SRC_DIR})

# Find GMP (required by chiavdf verifier). Prefer pkg-config, fall back to direct link.
find_path(GMP_INCLUDE_DIR gmp.h)
find_library(GMP_LIBRARY NAMES gmp)
find_library(GMPXX_LIBRARY NAMES gmpxx)
if(GMP_INCLUDE_DIR)
  target_include_directories(bitcoin_vdf PRIVATE ${GMP_INCLUDE_DIR})
endif()
if(GMPXX_LIBRARY)
  target_link_libraries(bitcoin_vdf PRIVATE ${GMPXX_LIBRARY})
endif()
if(GMP_LIBRARY)
  target_link_libraries(bitcoin_vdf PRIVATE ${GMP_LIBRARY})
endif()


include(InstallBinaryComponent)

if(ENABLE_WALLET)
  add_subdirectory(wallet)

  if(BUILD_WALLET_TOOL)
    add_executable(bitcoin-wallet
      bitcoin-wallet.cpp
      init/bitcoin-wallet.cpp
      wallet/wallettool.cpp
    )
    add_windows_resources(bitcoin-wallet bitcoin-wallet-res.rc)
    add_windows_application_manifest(bitcoin-wallet)
    target_link_libraries(bitcoin-wallet
      core_interface
      bitcoin_wallet
      bitcoin_common
      bitcoin_util
      bitcoin_node
      Boost::headers
    )
    install_binary_component(bitcoin-wallet HAS_MANPAGE)
  endif()
endif()


# P2P and RPC server functionality used by `bitcoind` and `bitcoin-qt` executables.
add_library(bitcoin_node STATIC EXCLUDE_FROM_ALL
  addrdb.cpp
  addrman.cpp
  banman.cpp
  bip324.cpp
  blockencodings.cpp
  blockfilter.cpp
  consensus/tx_verify.cpp
  consensus/model_verification.cpp
  dbwrapper.cpp
  deploymentstatus.cpp
  flatfile.cpp
  headerssync.cpp
  httprpc.cpp
  httpserver.cpp
  i2p.cpp
  index/base.cpp
  index/blockfilterindex.cpp
  index/coinstatsindex.cpp
  index/icu_acceptance_index.cpp
  index/txindex.cpp
  init.cpp
  kernel/chain.cpp
  kernel/checks.cpp
  kernel/coinstats.cpp
  kernel/context.cpp
  kernel/cs_main.cpp
  kernel/disconnected_transactions.cpp
  kernel/mempool_removal_reason.cpp
  mapport.cpp
  modeldb.cpp
  net.cpp
  onion_diversity.cpp
  net_processing.cpp
  netgroup.cpp
  node/abort.cpp
  node/blockmanager_args.cpp
  node/blockmeta.cpp
  node/blockstorage.cpp
  node/caches.cpp
  node/chainstate.cpp
  node/chainstatemanager_args.cpp
  node/coin.cpp
  node/coins_view_args.cpp
  node/connection_types.cpp
  node/context.cpp
  node/database_args.cpp
  node/eviction.cpp
  node/interface_ui.cpp
  node/interfaces.cpp
  node/kernel_notifications.cpp
  node/mempool_args.cpp
  node/mempool_persist.cpp
  node/mempool_persist_args.cpp
  node/miner.cpp
  node/mini_miner.cpp
  node/minisketchwrapper.cpp
  node/peerman_args.cpp
  node/psbt.cpp
  node/timeoffsets.cpp
  node/transaction.cpp
  node/txdownloadman_impl.cpp
  node/txreconciliation.cpp
  node/utxo_snapshot.cpp
  node/warnings.cpp
  node/extapi.cpp
  node/model_validation_shims.cpp
  noui.cpp
  policy/ephemeral_policy.cpp
  policy/fees.cpp
  policy/fees_args.cpp
  policy/packages.cpp
  policy/rbf.cpp
  policy/settings.cpp
  policy/truc_policy.cpp
  rest.cpp
  rpc/blockchain.cpp
  rpc/external_signer.cpp
  rpc/fees.cpp
  rpc/mempool.cpp
  rpc/mining.cpp
  rpc/net.cpp
  rpc/node.cpp
  rpc/output_script.cpp
  rpc/rawtransaction.cpp
  rpc/rotateicu.cpp
  rpc/scalar.cpp
  rpc/option_series.cpp
  rpc/server.cpp
  rpc/server_util.cpp
  rpc/signmessage.cpp
  rpc/bip322.cpp
  rpc/txoutproof.cpp
  rpc/custom.cpp
  rpc/cosign.cpp
  rpc/proof_verify.cpp
  script/sigcache.cpp
  signet.cpp
  torcontrol.cpp
  txdb.cpp
  txgraph.cpp
  txmempool.cpp
  txorphanage.cpp
  txrequest.cpp
  validation.cpp
  validationadvisory.cpp
  validationapi.cpp
  validationapi_mock.cpp
  validationinterface.cpp
  versionbits.cpp
  verification/pow_v3.cpp
  verification/bcred_table_r1024.cpp
  verification/quick_verifier.cpp
  verification/verification_utils.cpp
  $<$<TARGET_EXISTS:bitcoin_wallet>:wallet/init.cpp>
  $<$<NOT:$<TARGET_EXISTS:bitcoin_wallet>>:dummywallet.cpp>
)
# if(ENABLE_WALLET AND BUILD_WALLET_TOOL)
#   target_link_libraries(bitcoin-wallet
#     PRIVATE
#       bitcoin_node
#   )
# endif()


target_link_libraries(bitcoin_node
  PRIVATE
    core_interface
    bitcoin_common
    secp256k1
    bitcoin_vdf
    bitcoin_util
    $<TARGET_NAME_IF_EXISTS:bitcoin_zmq>
    leveldb
    minisketch
    univalue
    Boost::headers
    $<TARGET_NAME_IF_EXISTS:libevent::core>
    $<TARGET_NAME_IF_EXISTS:libevent::extra>
    $<TARGET_NAME_IF_EXISTS:libevent::pthreads>
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
  PUBLIC
    $<$<BOOL:${WITH_ZMQ}>:zeromq>
    OpenSSL::SSL
    OpenSSL::Crypto
    $<TARGET_NAME_IF_EXISTS:Argon2::Argon2>
    $<$<PLATFORM_ID:Windows>:ws2_32>
    $<$<PLATFORM_ID:Windows>:wsock32>
    $<$<PLATFORM_ID:Windows>:crypt32>
    $<$<PLATFORM_ID:Windows>:iphlpapi>
    $<$<PLATFORM_ID:Windows>:gdi32>
    $<$<PLATFORM_ID:Windows>:user32>
    $<$<PLATFORM_ID:Windows>:advapi32>
)


# Bitcoin Core bitcoind.
if(BUILD_DAEMON)
    add_executable(bitcoind
      bitcoind.cpp
      init/bitcoind.cpp
    )
    add_windows_resources(bitcoind bitcoind-res.rc)
    add_windows_application_manifest(bitcoind)
    target_link_libraries(bitcoind
      core_interface
      bitcoin_node
      $<TARGET_NAME_IF_EXISTS:bitcoin_wallet>
      $<$<BOOL:${WITH_ZMQ}>:zeromq>
    )
  install_binary_component(bitcoind HAS_MANPAGE)
endif()
if(ENABLE_IPC AND BUILD_DAEMON)
  add_executable(bitcoin-node
    bitcoind.cpp
    init/bitcoin-node.cpp
  )
  target_link_libraries(bitcoin-node
    core_interface
    bitcoin_node
    bitcoin_ipc
    $<TARGET_NAME_IF_EXISTS:bitcoin_wallet>
  )
  install_binary_component(bitcoin-node)
endif()

if(ENABLE_IPC AND BUILD_TESTS)
    # bitcoin_ipc_test library target is defined here in src/CMakeLists.txt
    # instead of src/test/CMakeLists.txt so capnp files in src/test/ are able to
    # reference capnp files in src/ipc/capnp/ by relative path. The Cap'n Proto
    # compiler only allows importing by relative path when the importing and
    # imported files are underneath the same compilation source prefix, so the
    # source prefix must be src/, not src/test/
    add_library(bitcoin_ipc_test STATIC EXCLUDE_FROM_ALL
      test/ipc_test.cpp
    )
    target_capnp_sources(bitcoin_ipc_test ${PROJECT_SOURCE_DIR}
      test/ipc_test.capnp
    )
    add_dependencies(bitcoin_ipc_test bitcoin_ipc_headers)
endif()


add_library(bitcoin_cli STATIC EXCLUDE_FROM_ALL
  compat/stdin.cpp
  rpc/client.cpp
)
target_link_libraries(bitcoin_cli
  PUBLIC
    core_interface
    univalue
)


# Bitcoin Core RPC client
if(BUILD_CLI)
  add_executable(bitcoin-cli bitcoin-cli.cpp)
  add_windows_resources(bitcoin-cli bitcoin-cli-res.rc)
  add_windows_application_manifest(bitcoin-cli)
  target_link_libraries(bitcoin-cli
    core_interface
    bitcoin_cli
    bitcoin_common
    bitcoin_util
    libevent::core
    libevent::extra
  )
  install_binary_component(bitcoin-cli HAS_MANPAGE)
endif()


if(BUILD_TX)
  add_executable(bitcoin-tx bitcoin-tx.cpp)
  add_windows_resources(bitcoin-tx bitcoin-tx-res.rc)
  add_windows_application_manifest(bitcoin-tx)
  target_link_libraries(bitcoin-tx
    core_interface
    bitcoin_common
    bitcoin_util
    univalue
  )
  install_binary_component(bitcoin-tx HAS_MANPAGE)
endif()


if(BUILD_UTIL)
  add_executable(bitcoin-util bitcoin-util.cpp)
  add_windows_resources(bitcoin-util bitcoin-util-res.rc)
  add_windows_application_manifest(bitcoin-util)
  target_link_libraries(bitcoin-util
    core_interface
    bitcoin_common
    bitcoin_util
  )
  install_binary_component(bitcoin-util HAS_MANPAGE)
endif()


if(BUILD_GUI)
  add_subdirectory(qt)
endif()


if(BUILD_KERNEL_LIB)
  add_subdirectory(kernel)
endif()

if(BUILD_UTIL_CHAINSTATE)
  add_executable(bitcoin-chainstate
    bitcoin-chainstate.cpp
  )
  # TODO: The `SKIP_BUILD_RPATH` property setting can be deleted
  #       in the future after reordering Guix script commands to
  #       perform binary checks after the installation step.
  # Relevant discussions:
  # - https://github.com/hebasto/bitcoin/pull/236#issuecomment-2183120953
  # - https://github.com/bitcoin/bitcoin/pull/30312#issuecomment-2191235833
  set_target_properties(bitcoin-chainstate PROPERTIES
    SKIP_BUILD_RPATH OFF
  )
  target_link_libraries(bitcoin-chainstate
    PRIVATE
      core_interface
      bitcoinkernel
  )
endif()


add_subdirectory(test/util)
if(BUILD_BENCH)
  add_subdirectory(bench)
endif()

if(BUILD_TESTS)
  add_subdirectory(test)
endif()

if(BUILD_FUZZ_BINARY)
  add_subdirectory(test/fuzz)
endif()
