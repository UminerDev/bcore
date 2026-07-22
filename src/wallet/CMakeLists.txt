# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Wallet functionality used by bitcoind and bitcoin-wallet executables.
add_library(bitcoin_wallet STATIC EXCLUDE_FROM_ALL
  asset_registration.cpp
  coincontrol.cpp
  coinselection.cpp
  context.cpp
  contract.cpp
  crypter.cpp
  db.cpp
  dump.cpp
  external_signer_scriptpubkeyman.cpp
  feebumper.cpp
  fees.cpp
  interfaces.cpp
  load.cpp
  migrate.cpp
  receive.cpp
  rpc/addresses.cpp
  rpc/api_model_registration.cpp
  rpc/assets.cpp
  rpc/adaptor.cpp
  rpc/musig_adaptors.cpp
  rpc/contracts.cpp
  rpc/difficulty.cpp
  rpc/option_series.cpp
  rpc/scalar.cpp
  rpc/scalar_cfd.cpp
  rpc/backup.cpp
  rpc/coins.cpp
  rpc/compliance_root.cpp
  rpc/encrypt.cpp
  rpc/hd_witness.cpp
  rpc/pq.cpp
  rpc/signmessage.cpp
  rpc/spend.cpp
  rpc/transactions.cpp
  rpc/util.cpp
  rpc/vaults.cpp
  rpc/verify.cpp
  rpc/wallet.cpp
  pricing/discount_curve.cpp
  pricing/fx_matrix.cpp
  pricing/vol_surface.cpp
  pricing/correlation_matrix.cpp
  pricing/difficulty_curve.cpp
  pricing/scalar_forward_curve.cpp
  pricing/scalar_cfd_pricer.cpp
  pricing/difficulty_vol_surface.cpp
  pricing/pricing_context.cpp
  pricing/leg_valuator.cpp
  pricing/black_scholes.cpp
  pricing/spread_option.cpp
  pricing/repo_pricer.cpp
  pricing/forward_pricer.cpp
  pricing/difficulty_pricer.cpp
  pricing/calibrator.cpp
  pricing/rpc/pricing_market.cpp
  pricing/rpc/pricing_repo.cpp
  pricing/rpc/pricing_forward.cpp
  pricing/rpc/pricing_difficulty.cpp
  pricing/rpc/pricing_portfolio.cpp
  pricing/rpc/pricing_diagnostics.cpp
  scriptpubkeyman.cpp
  vaultregistry.cpp
  vault_signing.cpp
  spend.cpp
  keywrap_utils.cpp
  sqlite.cpp
  transaction.cpp
  wallet.cpp
  walletdb.cpp
  crosschainmanager.cpp
  ethhtlcbackend.cpp
  walletutil.cpp
)
target_link_libraries(bitcoin_wallet
  PRIVATE
    secp256k1
  PUBLIC
    core_interface
    bitcoin_common
    $<TARGET_NAME_IF_EXISTS:unofficial::sqlite3::sqlite3>
    $<TARGET_NAME_IF_EXISTS:SQLite::SQLite3>
    univalue
    Boost::headers
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
)

set(_bitcoin_wallet_dl ${CMAKE_DL_LIBS})
if(NOT _bitcoin_wallet_dl)
  find_library(_bitcoin_wallet_dl dl)
endif()
if(_bitcoin_wallet_dl)
  target_link_libraries(bitcoin_wallet PUBLIC ${_bitcoin_wallet_dl})
endif()
