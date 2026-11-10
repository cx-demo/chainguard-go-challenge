# Chainguard Solutions Engineer Technical Challenge

## Overview

This technical challenge evaluates your practical skills in Linux systems, containerization, Kubernetes, and secure software supply chain practices. You will containerize an application using multiple approaches, analyze security posture, and present your findings.

**Time Allocation:** 4-8 hours (take-home)

**Deliverable:** Working implementation + technical presentation

> **Note:** This challenge is comprehensive by design. We understand you may not complete every task, and that's perfectly acceptable. We're more interested in your problem-solving approach, technical decisions, and how you navigate challenges than achieving full completion. Focus on demonstrating your thought process and documenting your journey.

## Environment Setup

Spin up a Linux virtual machine using your preferred virtualization platform. Within this VM:

- Install a container engine of your choice
- Deploy a local Kubernetes cluster of your choice
- Deploy a local container registry of your choice

Document your tool choices and reasoning.

## Container Security Fundamentals

Work with the Go application from the Chainguard demo repository:

```sh
git clone https://github.com/chainguard-dev/hello-melange-apko
cd hello-melange-apko/go
```

### Requirements

#### 1. Containerization

- Create a single-stage Dockerfile
- Create a multi-stage Dockerfile
- Use any base image of your choice

#### 2. Security Analysis

- Scan both containers with a CVE scanner
- Document all vulnerabilities found
- Compare results between both approaches

#### 3. Remediation

- Patch the Go application (and its dependencies)
- Update or optimize base images as needed
- Rescan and document improvements

#### 4. Supply Chain Security

- Generate SBOM for each container
- Sign all container images
- Push signed images to your local registry

#### 5. Deployment

- Deploy as a standalone container
- Deploy to your Kubernetes cluster
- Validate both deployments are functional

### Deliverables

- All Dockerfiles
- Vulnerability scan reports (before/after)
- SBOM files
- Kubernetes manifests
- Documentation of findings and methodology

## Presentation & Interview

Prepare a 30-45 minute technical presentation covering:

### Environment & Architecture (5-10 min)

- Setup decisions and rationale
- Tool selection justification

### Deep Dive (10-15 min)

- Dockerfile design choices
- Security findings and remediation approach
- SBOM insights
- Production challenges for traditional container builds

### Q&A (5-10 min)

- Security best practices
- Supply chain considerations
- Kubernetes security
- Operational challenges

Prepare to walk live through your setup, Dockerfiles as well as the results of your findings (the results can be presented using a slide deck).

## Evaluation Criteria

Your presentation will be assessed on:

- Problem-solving approach and technical reasoning
- Security awareness and analysis depth
- Quality of work completed (over quantity)
- Code quality and documentation (where needed)
- Communication and presentation skills
- Ability to articulate challenges and tradeoffs
