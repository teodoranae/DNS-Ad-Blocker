keywords = ['facebook', 'google', 'reddit', 'amazon', 'linkedin']
companii = {k: set() for k in keywords}

with open("blocked_domains.txt", "r") as f:
    for linie in f:
        domeniu = linie.strip().lower()
        for cuvant in keywords:
            if cuvant in domeniu:
                companii[cuvant].add(domeniu)

with open("statistici.txt", "w") as f_out:
    for companie, domenii in companii.items():
        f_out.write(f"Compania '{companie}' are {len(domenii)} domenii blocate:\n")
        for d in sorted(domenii):
            f_out.write(f"  - {d}\n")
        f_out.write("\n")
