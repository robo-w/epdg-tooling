# ePDG Tooling

This repository is a collection of tools used and/or developed in the scope
of the master's thesis `Automated Phreaking: Consolidation of VoLTE and VoWiFi Security Testing`
at TU Wien in 2026.

BibTex citation:

```text
@mastersthesis{wittek_automated_2026,
	author = {Wittek, Robert},
	title = {Automated {Phreaking}: {Consolidation} of {VoLTE} and {VoWiFi} {Security} {Testing}},
	url = {https://repositum.tuwien.at/handle/20.500.12708/232364},
	copyright = {http://rightsstatements.org/vocab/InC/1.0/},
	doi = {10.34726/hss.2026.139547},
	language = {en},
	school = {Technische Universität Wien},
	year = {2026},
	address = {Wien},
}
```

## Structure of the Repository

Following tools are part of this repository:

* [3gpp_dns_query](3gpp_dns_query/README.md) - Helper scripts to query the ePDG DNS records
* [epdg-peek](epdg-peek/README.md) - Containerized toolset to test various security configurations in the IMS network of a provider
* [sa-capture-adb](sa-capture-adb): Script to dump all created IPsec Security Associations (SAs) from a rooted Android device via ADB to Wireshark format
* [tmuxinator](tmuxinator/README.md): `tmuxinator` project files to automate scenarios


## License

The project is licensed under [GNU General Public License v3.0 (GPLv3)](LICENSE),
unless stated otherwise in specific files, for example when original license conditions require a different license.


## Known Limitations

The tools were developed and tested in Europe, therefore 2-digit MNCs are tested to be working.
All tools were built with support of 3-digit MNCs in mind, but so far not tested.

Algorithms and protocols were implemented when needed.
SIP registration authentication is for example limited to the legacy `AKAv1-MD5` algorithm.


## Disclaimer

The tools in this repository were created for research purposes during the work on the master's thesis.
As stated in the license in detail, there is no warranty or liability given.
It is strongly advised to use all the tools only in a controlled environment and under monitoring of the results. 
