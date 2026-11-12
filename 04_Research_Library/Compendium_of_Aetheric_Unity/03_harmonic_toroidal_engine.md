# Harmonic Toroidal Engine — System Overview

**Source:** Google Drive (`Public Overview Harmonic Toroidal Engine.pdf`)  
**Architecture Type:** Closed-Loop Sympathetic Resonance Engine

---

## Closed-Loop Energy Circulation Diagram

```mermaid
flowchart TB
    CAP["<b>4. The Resonance Cap (The Ceiling)</b><br/>Catches rising central energy pillar;<br/>reflects thrust back into outer walls"]
    
    CORE["<b>1. The Central Driver (The Core)</b><br/>Generates initial 1121 Hz pulse;<br/>drives upward & outward thrust"]
    
    WALLS["<b>2. The Containment Field (The Walls)</b><br/>Heavy outer magnetic coils;<br/>bends outward force downward & inward"]
    
    BASE["<b>3. The Stabilizing Base (The Floor)</b><br/>Grounded foundation;<br/>absorbs turbulence & maintains alignment"]

    CORE -- "Upward Thrust" --> CAP
    CORE -- "Outward Thrust" --> WALLS
    CAP -- "Reflects Energy Downward" --> WALLS
    WALLS -- "Bends Force Inward/Downward" --> BASE
    BASE -- "Grounded Stabilization & Return" --> CORE

    classDef core fill:#7c2d12,stroke:#fb923c,stroke-width:2px,color:#fff;
    classDef cap fill:#1e1b4b,stroke:#818cf8,stroke-width:2px,color:#e0e7ff;
    classDef walls fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef base fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#ecfdf5;

    class CORE core;
    class CAP cap;
    class WALLS walls;
    class BASE base;
```

---

## Engineering Principles & Comparison

| Feature | Standard Mechanical Systems | Harmonic Toroidal Engine |
| :--- | :--- | :--- |
| **Energy Flow** | Open-loop; generates power and allows excess to dissipate. | **Closed-loop toroidal field**; continuously recycles kinetic and magnetic forces. |
| **Control Method** | Brute-force mechanical manipulation and heavy copper conduction. | **Sympathetic resonance**; hardware is tuned to natural vibrational frequencies (like a musical instrument). |
| **Boundary Control** | Physical friction and rigid containment barriers. | Magnetic deflection (**Containment Walls**) and upper reflection (**Resonance Cap**). |