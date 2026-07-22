# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Do not use generator expressions in test sources because the
# SOURCES property is processed to gather test suite macros.
add_executable(test_bitcoin
  main.cpp
  addrman_tests.cpp
  allocator_tests.cpp
  amount_tests.cpp
  argsman_tests.cpp
  arith_uint256_tests.cpp
  asset_arithmetic_tests.cpp
  assets_bond_tests.cpp
  asset_distribution_tests.cpp
  asset_edge_tests.cpp
  asset_icu_sighash_tests.cpp
  asset_kyc_delegation_tests.cpp
  asset_kyc_sighash_tests.cpp
  asset_registry_tests.cpp
  asset_tests.cpp
  asset_validation_tests.cpp
  asset_zk_binding_tests.cpp
  asset_zk_consensus_tests.cpp
  asset_zk_robustness_tests.cpp
  asset_zk_tests.cpp
  asset_zk_validation_tests.cpp
  icu_payload_tests.cpp
  icu_acceptance_tests.cpp
  icu_context_tests.cpp
  banman_tests.cpp
  base32_tests.cpp
  blockmeta_tests.cpp
  base58_tests.cpp
  base64_tests.cpp
  bech32_tests.cpp
  bip32_tests.cpp
  bip324_tests.cpp
  blockchain_tests.cpp
  blockencodings_tests.cpp
  blockfilter_index_tests.cpp
  blockfilter_tests.cpp
  chainwork_nbits_selection_tests.cpp
  blockmanager_tests.cpp
  bloom_tests.cpp
  bswap_tests.cpp
  chainstate_asset_guard_tests.cpp
  chainstate_write_tests.cpp
  checkqueue_tests.cpp
  cluster_linearize_tests.cpp
  coins_asset_overlay_tests.cpp
  coins_tests.cpp
  coinscachepair_tests.cpp
  coinstatsindex_tests.cpp
  common_url_tests.cpp
  compilerbug_tests.cpp
  compress_tests.cpp
  crypto_tests.cpp
  cuckoocache_tests.cpp
  dbwrapper_tests.cpp
  denialofservice_tests.cpp
  descriptor_tests.cpp
  disconnected_transactions.cpp
  fee_accumulator_tests.cpp
  feefrac_tests.cpp
  flatfile_tests.cpp
  fs_tests.cpp
  getarg_tests.cpp
  groth16_golden_tests.cpp
  hash_tests.cpp
  headers_sync_chainwork_tests.cpp
  httpserver_tests.cpp
  i2p_tests.cpp
  interfaces_tests.cpp
  key_io_tests.cpp
  key_tests.cpp
  model_registration_sanity_tests.cpp
  model_challenge_tests.cpp
  logging_tests.cpp
  mempool_asset_tests.cpp
  mempool_tests.cpp
  merkle_tests.cpp
  merkleblock_tests.cpp
  model_validation_tests.cpp
  difficulty_cfd_tests.cpp
  difficulty_cfd_script_tests.cpp
  difficulty_cfd_validation_tests.cpp
  difficulty_nbits_tests.cpp
  scalar_cfd_leaf_tests.cpp
  scalar_cfd_payout_tests.cpp
  scalar_cfd_snapshot_tests.cpp
  scalar_cfd_eval_tests.cpp
  scalar_cfd_validation_tests.cpp
  header_flags_malleability_tests.cpp
  model_reorg_tests.cpp
  tick_accumulator_tests.cpp
  miner_tests.cpp
  pow_adjbits_ratio_tests.cpp
  pow_commitment_tests.cpp
  pow_v3_vectors_tests.cpp
  quick_verifier_v3_tests.cpp
  pow_adjbits_behavior_tests.cpp
  difficulty_mixed_models_tests.cpp
  pow_blob_mismatch_tests.cpp
  tick_reorg_tests.cpp
  consensus_vdf_flag_tests.cpp
  miniminer_tests.cpp
  miniscript_tests.cpp
  minisketch_tests.cpp
  multisig_tests.cpp
  net_peer_connection_tests.cpp
  net_peer_eviction_tests.cpp
  net_tests.cpp
  validation_quick_full_tests.cpp
  validation_reentry_dedup_tests.cpp
  netbase_tests.cpp
  node_warnings_tests.cpp
  onion_diversity_tests.cpp
  orphanage_tests.cpp
  pcp_tests.cpp
  peerman_tests.cpp
  pmt_tests.cpp
  policy_fee_tests.cpp
  policy_covenant_tests.cpp
  policyestimator_tests.cpp
  pool_tests.cpp
  pow_blob_tests.cpp
  pow_retarget_overflow_tests.cpp
  pow_tests.cpp
  psbt_mldsa_tests.cpp
  prevector_tests.cpp
  raii_event_tests.cpp
  random_tests.cpp
  rbf_tests.cpp
  rest_tests.cpp
  result_tests.cpp
  reverselock_tests.cpp
  rpc_tests.cpp
  rpc_assets_tests.cpp
  sanity_tests.cpp
  scheduler_tests.cpp
  script_p2sh_tests.cpp
  script_parse_tests.cpp
  script_segwit_tests.cpp
  script_standard_tests.cpp
  script_tests.cpp
  script_covenant_tests.cpp
  scriptnum_tests.cpp
  serfloat_tests.cpp
  serialize_tests.cpp
  settings_tests.cpp
  sighash_tests.cpp
  sigopcount_tests.cpp
  skiplist_tests.cpp
  sock_tests.cpp
  span_tests.cpp
  streams_tests.cpp
  sync_tests.cpp
  system_tests.cpp
  testnet4_miner_tests.cpp
  timeoffsets_tests.cpp
  torcontrol_tests.cpp
  transaction_tests.cpp
  translation_tests.cpp
  txdownload_tests.cpp
  txindex_tests.cpp
  txpackage_tests.cpp
  txreconciliation_tests.cpp
  txrequest_tests.cpp
  txvalidation_tests.cpp
  txvalidationcache_tests.cpp
  uint256_tests.cpp
  util_string_tests.cpp
  util_tests.cpp
  util_threadnames_tests.cpp
  util_trace_tests.cpp
  validation_block_tests.cpp
  validation_chainstate_tests.cpp
  validation_chainstatemanager_tests.cpp
  validation_asset_tests.cpp
  validation_flush_tests.cpp
  validation_tests.cpp
  validationadvisory_tests.cpp
  extapi_tick_tests.cpp
  extapi_response_validation_tests.cpp
  util/model_test_helpers.cpp
  validationinterface_tests.cpp
  versionbits_tests.cpp
  validationapi_tests.cpp
  ../verification/test/test_quick_verify.cpp
  vdf_verify_tests.cpp
  spv_hysteresis_tests.cpp
  spv_tick_anchor_tests.cpp
  headers_ext_branch_negative_tests.cpp
  net_processing_headers_ext_smoke_tests.cpp
  net_processing_vdf_eviction_tests.cpp
  proof_bucket_dedup_tests.cpp
  ema_tick_tests.cpp
  spv_sampling_quick_plumbing_tests.cpp
  vdf_roundtrip_tests.cpp
  cosign_tests.cpp
)

include(TargetDataSources)
target_json_data_sources(test_bitcoin
  data/base58_encode_decode.json
  data/bip341_wallet_vectors.json
  data/blockfilters.json
  data/key_io_invalid.json
  data/key_io_valid.json
  data/script_tests.json
  data/sighash.json
  data/tx_invalid.json
  data/tx_valid.json
)
target_raw_data_sources(test_bitcoin NAMESPACE test::data
  data/asmap.raw
)

add_windows_application_manifest(test_bitcoin)

target_link_libraries(test_bitcoin
  core_interface
  test_util
  bitcoin_cli
  bitcoin_node
  bitcoin_consensus
  minisketch
  secp256k1
  Boost::headers
  Boost::locale
  Boost::thread
  libevent::extra
  $<$<BOOL:${WITH_ZMQ}>:zeromq>
)

if(ENABLE_WALLET)
  add_subdirectory(${PROJECT_SOURCE_DIR}/src/wallet/test wallet)
endif()

if(ENABLE_IPC)
  target_link_libraries(bitcoin_ipc_test
    PRIVATE
      core_interface
      univalue
      Boost::headers
  )

  target_sources(test_bitcoin
    PRIVATE
      ipc_tests.cpp
  )
  target_link_libraries(test_bitcoin bitcoin_ipc_test bitcoin_ipc)
endif()

function(add_boost_test source_file)
  if(NOT EXISTS ${source_file})
    return()
  endif()

  file(READ "${source_file}" source_file_content)
  string(REGEX
    MATCH "(BOOST_FIXTURE_TEST_SUITE|BOOST_AUTO_TEST_SUITE)\\(([A-Za-z0-9_]+)"
    test_suite_macro "${source_file_content}"
  )
  string(REGEX
    REPLACE "(BOOST_FIXTURE_TEST_SUITE|BOOST_AUTO_TEST_SUITE)\\(" ""
    test_suite_name "${test_suite_macro}"
  )
  if(test_suite_name)
    add_test(NAME ${test_suite_name}
      COMMAND test_bitcoin --run_test=${test_suite_name} --catch_system_error=no --log_level=test_suite -- DEBUG_LOG_OUT
    )
    set_property(TEST ${test_suite_name} PROPERTY
      SKIP_REGULAR_EXPRESSION "no test cases matching filter"
    )
  endif()
endfunction()

function(add_all_test_targets)
  get_target_property(test_source_dir test_bitcoin SOURCE_DIR)
  get_target_property(test_sources test_bitcoin SOURCES)
  foreach(test_source ${test_sources})
    cmake_path(IS_RELATIVE test_source result)
    if(result)
      cmake_path(APPEND test_source_dir ${test_source} OUTPUT_VARIABLE test_source)
    endif()
    add_boost_test(${test_source})
  endforeach()
endfunction()

add_all_test_targets()

install_binary_component(test_bitcoin)

add_executable(manual_test test_proofblob_roundtrip.cpp)
target_link_libraries(manual_test
  core_interface
  bitcoin_cli
  bitcoin_node
  bitcoin_consensus
  minisketch
  secp256k1
  Boost::headers
  libevent::extra
)

# Mock cosign bridge for C++ unit tests
add_executable(mock_cosign_bridge mock_cosign_bridge.cpp)
target_link_libraries(mock_cosign_bridge
  core_interface
  univalue
  bitcoin_util
)

# Make test_bitcoin depend on mock_cosign_bridge so it's always built
add_dependencies(test_bitcoin mock_cosign_bridge)

# Generate genuine VDF proofs through the same implementation used by the
# node. The PyPI chiavdf API does not expose TensorCash's hash-to-form helper,
# so functional tests invoke this binary instead of weakening verification.
add_executable(vdf_test_helper vdf_test_helper.cpp)
target_link_libraries(vdf_test_helper
  core_interface
  bitcoin_util
  bitcoin_vdf
)
add_dependencies(test_bitcoin vdf_test_helper)

# ML-DSA test helper for functional tests (key generation and signing)
if(LIBOQS_LIB)
  # Add ML-DSA unit tests to test_bitcoin
  target_sources(test_bitcoin PRIVATE crypto_mldsa_tests.cpp)

  add_executable(mldsa_test_helper mldsa_test_helper.cpp)
  target_link_libraries(mldsa_test_helper
    core_interface
    bitcoin_crypto
    ${LIBOQS_LIB}
  )
  target_include_directories(mldsa_test_helper PRIVATE ${LIBOQS_INCLUDE_DIR})
  target_compile_definitions(mldsa_test_helper PRIVATE ENABLE_MLDSA)
  add_dependencies(test_bitcoin mldsa_test_helper)
  target_compile_definitions(test_bitcoin PRIVATE ENABLE_MLDSA)
endif()
