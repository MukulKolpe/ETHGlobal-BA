"use client";

import type React from "react";
import { useState } from "react";
import Header from "@/components/header";
import { ArrowLeft, Loader2, AlertCircle, CheckCircle2 } from "lucide-react";
import Link from "next/link";

export default function CreateOrganization() {
  const [currentStep, setCurrentStep] = useState<"org" | "deposit">("org");
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [createdOrgId, setCreatedOrgId] = useState<string | null>(null);

  // Organization form state
  const [orgFormData, setOrgFormData] = useState({
    orgName: "",
    adminAddress: "",
  });

  // Deposit form state
  const [depositFormData, setDepositFormData] = useState({
    tokenAddress: "",
    amount: "",
  });
  const [approvalState, setApprovalState] = useState<
    "none" | "pending" | "approved"
  >("none");

  const supportedTokens = [
    { symbol: "USDC", address: "0xcA943E825B6768A75c9814E318E98Faf90fD8CD9" },
    { symbol: "USDT", address: "0x30E9b6B0d161cBd5Ff8cf904Ff4FA43Ce66AC346" },
    { symbol: "LINK", address: "0xE4aB69C077896252FAFBD49EFD26B5D171A32410" },
  ];

  const handleOrgInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setOrgFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
    if (errors[name]) {
      setErrors((prev) => ({ ...prev, [name]: "" }));
    }
  };

  const validateOrgForm = () => {
    const newErrors: Record<string, string> = {};

    if (!orgFormData.orgName.trim()) {
      newErrors.orgName = "Organization name is required";
    }

    if (!orgFormData.adminAddress.trim()) {
      newErrors.adminAddress = "Admin address is required";
    } else if (!/^0x[a-fA-F0-9]{40}$/.test(orgFormData.adminAddress)) {
      newErrors.adminAddress = "Invalid Ethereum address format";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleCreateOrganization = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateOrgForm()) return;

    setLoading(true);
    try {
      // const orgId = ethers.id(orgFormData.orgName)
      // await contract.registerOrganization(orgId, orgFormData.adminAddress)

      // For now, generate org ID from name
      const orgId =
        "0x" + Buffer.from(orgFormData.orgName).toString("hex").slice(0, 64);

      console.log("[v0] Creating organization:", {
        orgId,
        admin: orgFormData.adminAddress,
        name: orgFormData.orgName,
      });

      await new Promise((resolve) => setTimeout(resolve, 2000));

      setCreatedOrgId(orgId);
      setCurrentStep("deposit");
    } catch (error) {
      setErrors({ submit: "Failed to create organization" });
    } finally {
      setLoading(false);
    }
  };

  const handleDepositInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setDepositFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSelectToken = (tokenAddress: string) => {
    setDepositFormData((prev) => ({
      ...prev,
      tokenAddress,
    }));
  };

  const handleApproveToken = async () => {
    if (!depositFormData.amount) {
      setErrors({ amount: "Please enter an amount" });
      return;
    }

    if (Number.parseFloat(depositFormData.amount) <= 0) {
      setErrors({ amount: "Amount must be greater than 0" });
      return;
    }

    setLoading(true);
    try {
      // Check current allowance: const allowance = await token.allowance(userAddress, contractAddress)
      // If allowance < amount: await token.approve(contractAddress, amount)

      console.log("[v0] Approving token:", {
        token: depositFormData.tokenAddress,
        amount: depositFormData.amount,
      });

      setApprovalState("pending");
      await new Promise((resolve) => setTimeout(resolve, 2000));
      setApprovalState("approved");
      setErrors({});
    } catch (error) {
      setErrors({ approval: "Failed to approve token" });
      setApprovalState("none");
    } finally {
      setLoading(false);
    }
  };

  const handleDeposit = async () => {
    if (approvalState !== "approved") {
      setErrors({ approval: "Please approve the token first" });
      return;
    }

    if (!createdOrgId) {
      setErrors({ submit: "Organization ID not found" });
      return;
    }

    setLoading(true);
    try {
      // await contract.depositLiquidity(createdOrgId, depositFormData.tokenAddress, depositFormData.amount)

      console.log("[v0] Depositing liquidity:", {
        orgId: createdOrgId,
        token: depositFormData.tokenAddress,
        amount: depositFormData.amount,
      });

      await new Promise((resolve) => setTimeout(resolve, 2000));
      setErrors({});
      // Reset form after successful deposit
      setDepositFormData({ tokenAddress: "", amount: "" });
      setApprovalState("none");
    } catch (error) {
      setErrors({ deposit: "Failed to deposit liquidity" });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <main className="flex items-center justify-center px-4 py-12 min-h-[calc(100vh-80px)]">
        <div className="w-full max-w-md">
          {/* Back Button */}
          <Link href="/" className="mb-6 inline-block">
            <button className="inline-flex items-center text-muted-foreground hover:text-foreground text-sm transition-colors">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Home
            </button>
          </Link>

          {currentStep === "org" ? (
            <div className="bg-card border border-border/50 p-6 rounded-xl shadow-sm">
              <h1 className="text-2xl font-bold mb-1 text-foreground">
                Create Organization
              </h1>
              <p className="text-sm text-muted-foreground mb-6">
                Register your organization to start managing payroll
              </p>

              <form onSubmit={handleCreateOrganization} className="space-y-4">
                {/* Organization Name */}
                <div className="space-y-2">
                  <label
                    htmlFor="orgName"
                    className="text-sm text-foreground font-medium"
                  >
                    Organization Name
                  </label>
                  <input
                    id="orgName"
                    name="orgName"
                    type="text"
                    placeholder="Enter organization name"
                    value={orgFormData.orgName}
                    onChange={handleOrgInputChange}
                    disabled={loading}
                    className="w-full px-3 py-2 bg-input border border-border rounded-lg text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 disabled:opacity-50"
                  />
                  {errors.orgName && (
                    <p className="text-xs text-red-500">{errors.orgName}</p>
                  )}
                </div>

                {/* Admin Address */}
                <div className="space-y-2">
                  <label
                    htmlFor="adminAddress"
                    className="text-sm text-foreground font-medium"
                  >
                    Admin Wallet Address
                  </label>
                  <input
                    id="adminAddress"
                    name="adminAddress"
                    type="text"
                    placeholder="0x..."
                    value={orgFormData.adminAddress}
                    onChange={handleOrgInputChange}
                    disabled={loading}
                    className="w-full px-3 py-2 bg-input border border-border rounded-lg text-foreground placeholder:text-muted-foreground font-mono text-xs focus:outline-none focus:ring-2 focus:ring-primary/50 disabled:opacity-50"
                  />
                  {errors.adminAddress && (
                    <p className="text-xs text-red-500">
                      {errors.adminAddress}
                    </p>
                  )}
                </div>

                {/* Info Box */}
                <div className="bg-primary/5 border border-primary/20 rounded-lg p-3 mt-4">
                  <p className="text-xs text-foreground">
                    <span className="font-semibold">Note:</span> Ensure your
                    wallet is connected to the correct network.
                  </p>
                </div>

                {errors.submit && (
                  <p className="text-xs text-red-500">{errors.submit}</p>
                )}

                {/* Submit Button */}
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-primary hover:bg-primary/90 text-primary-foreground py-5 rounded-lg text-sm font-semibold mt-6 disabled:opacity-50 flex items-center justify-center"
                >
                  {loading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Creating...
                    </>
                  ) : (
                    "Create Organization"
                  )}
                </button>
              </form>

              {/* Info Section */}
              <div className="bg-secondary/30 border border-border/50 rounded-xl p-4 mt-6">
                <h2 className="text-sm font-bold mb-3 text-foreground">
                  What happens next?
                </h2>
                <ul className="space-y-2 text-xs text-muted-foreground">
                  <li className="flex gap-2">
                    <span className="text-primary font-bold flex-shrink-0">
                      1.
                    </span>
                    <span>Organization created with unique ID</span>
                  </li>
                  <li className="flex gap-2">
                    <span className="text-primary font-bold flex-shrink-0">
                      2.
                    </span>
                    <span>Admin gains full control</span>
                  </li>
                  <li className="flex gap-2">
                    <span className="text-primary font-bold flex-shrink-0">
                      3.
                    </span>
                    <span>Deposit liquidity in next step</span>
                  </li>
                </ul>
              </div>
            </div>
          ) : (
            <div className="bg-card border border-border/50 p-6 rounded-xl shadow-sm">
              <h1 className="text-2xl font-bold mb-1 text-foreground">
                Deposit Liquidity
              </h1>
              <p className="text-sm text-muted-foreground mb-6">
                Organization created! Now deposit liquidity to enable payroll
                management.
              </p>

              {/* Organization Created Info */}
              <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4 mb-6">
                <div className="flex items-start gap-3">
                  <CheckCircle2 className="h-5 w-5 text-green-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="font-semibold text-foreground text-sm">
                      Organization Created
                    </p>
                    <p className="text-xs text-muted-foreground mt-1 font-mono break-all">
                      {createdOrgId}
                    </p>
                  </div>
                </div>
              </div>

              {/* Token Selection */}
              {!depositFormData.tokenAddress ? (
                <div className="space-y-3">
                  <p className="text-sm text-muted-foreground">
                    Select a token to deposit
                  </p>
                  {supportedTokens.map((token) => (
                    <button
                      key={token.address}
                      onClick={() => handleSelectToken(token.address)}
                      className="w-full p-4 border border-border/50 rounded-lg hover:bg-secondary/30 hover:border-primary/50 transition-all text-left"
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-semibold text-foreground">
                            {token.symbol}
                          </p>
                          <p className="text-xs text-muted-foreground font-mono">
                            {token.address}
                          </p>
                        </div>
                      </div>
                    </button>
                  ))}
                </div>
              ) : approvalState !== "approved" ? (
                <div className="space-y-4">
                  <div className="space-y-2">
                    <label
                      htmlFor="amount"
                      className="text-sm text-foreground font-medium"
                    >
                      Amount
                    </label>
                    <input
                      id="amount"
                      name="amount"
                      type="number"
                      placeholder="0.00"
                      value={depositFormData.amount}
                      onChange={handleDepositInputChange}
                      disabled={loading}
                      className="w-full px-3 py-2 bg-input border border-border rounded-lg text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 disabled:opacity-50"
                    />
                    {errors.amount && (
                      <p className="text-xs text-red-500">{errors.amount}</p>
                    )}
                  </div>

                  <div className="bg-primary/10 border border-primary/20 rounded-lg p-4 space-y-3">
                    <div className="flex items-start gap-2">
                      <AlertCircle className="h-4 w-4 text-primary mt-0.5 flex-shrink-0" />
                      <div className="text-sm">
                        <p className="font-semibold text-foreground mb-1">
                          Token Approval Required
                        </p>
                        <p className="text-muted-foreground text-xs">
                          Approve the smart contract to spend{" "}
                          {depositFormData.amount || "0"}{" "}
                          {
                            supportedTokens.find(
                              (t) => t.address === depositFormData.tokenAddress
                            )?.symbol
                          }{" "}
                          tokens.
                        </p>
                      </div>
                    </div>
                  </div>

                  {errors.approval && (
                    <p className="text-xs text-red-500">{errors.approval}</p>
                  )}

                  <div className="flex gap-3 pt-2">
                    <button
                      onClick={() => {
                        setDepositFormData({ tokenAddress: "", amount: "" });
                        setApprovalState("none");
                      }}
                      disabled={loading}
                      className="flex-1 px-4 py-2 border border-border rounded-lg text-foreground hover:bg-secondary/30 transition-colors disabled:opacity-50 text-sm font-medium"
                    >
                      Back
                    </button>
                    <button
                      onClick={handleApproveToken}
                      disabled={loading || !depositFormData.amount}
                      className="flex-1 px-4 py-2 bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg transition-colors disabled:opacity-50 text-sm font-medium flex items-center justify-center"
                    >
                      {loading ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Approving...
                        </>
                      ) : (
                        "Approve Token"
                      )}
                    </button>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4">
                    <div className="flex items-center gap-3 mb-3">
                      <CheckCircle2 className="h-5 w-5 text-green-500" />
                      <p className="font-semibold text-foreground text-sm">
                        Token Approved
                      </p>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {
                        supportedTokens.find(
                          (t) => t.address === depositFormData.tokenAddress
                        )?.symbol
                      }{" "}
                      tokens are approved. Ready to deposit?
                    </p>
                  </div>

                  {/* Deposit Summary */}
                  <div className="bg-secondary/30 rounded-lg p-4 space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Token</span>
                      <span className="font-semibold text-foreground">
                        {
                          supportedTokens.find(
                            (t) => t.address === depositFormData.tokenAddress
                          )?.symbol
                        }
                      </span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Amount</span>
                      <span className="font-semibold text-foreground">
                        {depositFormData.amount}
                      </span>
                    </div>
                    <div className="flex justify-between text-sm pt-2 border-t border-border">
                      <span className="text-muted-foreground">Org ID</span>
                      <span className="font-mono text-xs text-foreground">
                        {createdOrgId?.slice(0, 10)}...
                      </span>
                    </div>
                  </div>

                  {errors.deposit && (
                    <p className="text-xs text-red-500">{errors.deposit}</p>
                  )}

                  <div className="flex gap-3 pt-2">
                    <button
                      onClick={() => setApprovalState("none")}
                      disabled={loading}
                      className="flex-1 px-4 py-2 border border-border rounded-lg text-foreground hover:bg-secondary/30 transition-colors disabled:opacity-50 text-sm font-medium"
                    >
                      Back
                    </button>
                    <button
                      onClick={handleDeposit}
                      disabled={loading}
                      className="flex-1 px-4 py-2 bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg transition-colors disabled:opacity-50 text-sm font-medium flex items-center justify-center"
                    >
                      {loading ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Depositing...
                        </>
                      ) : (
                        "Confirm Deposit"
                      )}
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
