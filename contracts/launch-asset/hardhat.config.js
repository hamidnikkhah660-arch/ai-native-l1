import { defineConfig } from "hardhat/config";

export default defineConfig({
  networks: {
    hardhatMainnet: {
      type: "edr-simulated",
      chainType: "l1",
      chainId: 31337
    }
  }
});
