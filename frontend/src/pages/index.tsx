"use client";
import Header from "@/components/header";
import Link from "next/link";
import { ArrowRight, Shield, Network, Zap } from "lucide-react";

export default function Home() {
  const features = [
    {
      icon: Shield,
      title: "Secured by Restaking",
      description:
        "Enterprise-grade security backed by restaking vaults and validator networks",
    },
    {
      icon: Network,
      title: "Cross-Chain Support",
      description:
        "Seamless payroll execution across multiple blockchains via Hyperlane",
    },
    {
      icon: Zap,
      title: "Instant Settlements",
      description: "Fast and efficient liquidity management with minimal fees",
    },
  ];

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Hero Section */}
        <section className="py-20 md:py-32">
          <div className="text-center mb-16">
            <h1 className="text-5xl md:text-6xl font-bold text-foreground mb-6 text-balance">
              Enterprise Payroll
              <span className="block text-transparent bg-clip-text bg-gradient-to-r from-primary to-accent">
                Across Chains
              </span>
            </h1>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto mb-8 text-balance">
              Manage global payroll with the security of restaking vaults and
              the reach of cross-chain infrastructure
            </p>
          </div>

          {/* CTA Section */}
          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center mb-20">
            <Link href="/organizations/create">
              <button className="bg-primary hover:bg-primary/90 text-primary-foreground px-6 py-3 text-lg rounded-lg font-medium transition inline-flex items-center gap-2">
                Create Organization
                <ArrowRight className="h-5 w-5" />
              </button>
            </Link>
          </div>
        </section>

        {/* Features Section */}
        <section className="py-16 mb-20">
          <h2 className="text-4xl font-bold text-center mb-16 text-foreground">
            Why CrossPay?
          </h2>
          <div className="grid md:grid-cols-3 gap-8">
            {features.map((feature, i) => {
              const Icon = feature.icon;
              return (
                <div
                  key={i}
                  className="bg-card border border-border/50 p-8 rounded-lg hover:border-primary/50 transition-colors"
                >
                  <Icon className="h-12 w-12 text-primary mb-4" />
                  <h3 className="text-xl font-bold mb-3 text-foreground">
                    {feature.title}
                  </h3>
                  <p className="text-muted-foreground">{feature.description}</p>
                </div>
              );
            })}
          </div>
        </section>

        {/* Quick Start Section */}
        <section className="py-16 mb-20">
          <div className="bg-gradient-to-r from-primary/10 to-accent/10 border border-primary/20 p-12 rounded-lg">
            <h2 className="text-3xl font-bold mb-6 text-foreground">
              Get Started in Minutes
            </h2>
            <div className="grid md:grid-cols-3 gap-8 mb-8">
              {[
                {
                  step: "1",
                  title: "Create Organization",
                  desc: "Set up your organization with admin credentials",
                },
                {
                  step: "2",
                  title: "Deposit Liquidity",
                  desc: "Fund your payroll vault with supported tokens",
                },
                {
                  step: "3",
                  title: "Process Payroll",
                  desc: "Execute payroll across supported chains",
                },
              ].map((item, i) => (
                <div key={i} className="flex flex-col items-center text-center">
                  <div className="w-12 h-12 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-lg font-bold mb-4">
                    {item.step}
                  </div>
                  <h3 className="font-bold mb-2 text-foreground">
                    {item.title}
                  </h3>
                  <p className="text-sm text-muted-foreground">{item.desc}</p>
                </div>
              ))}
            </div>
            <div className="flex justify-center pt-4">
              <Link href="/organizations/create">
                <button className="bg-primary hover:bg-primary/90 text-primary-foreground px-8 py-3 rounded-lg font-medium transition">
                  Start Now
                </button>
              </Link>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
