// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Source-owned compiler fixture. Never deployed or executed by acceptance.
contract RRInterfaceProbe {
    uint256 private counter;

    function pureProbe(uint32 value, address target) external pure returns (bytes32) {
        return keccak256(abi.encode(value, target));
    }
    function viewProbe() external view returns (uint256) { return counter; }
    function writeProbe(uint256 value) external { counter = value; }
    function payableProbe(uint256 value) external payable returns (uint256) {
        counter = value + msg.value;
        return counter;
    }
    function dynamicProbe(bytes calldata payload, uint256[] calldata values) external pure returns (uint256) {
        return payload.length + values.length;
    }
    fallback() external payable {
        assembly {
            if eq(shr(224, calldataload(0)), 0x11223344) {
                mstore(0, calldataload(4))
                return(0, 32)
            }
            stop()
        }
    }
}
