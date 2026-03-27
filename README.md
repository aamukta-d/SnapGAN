# SnapGAN: A Novel Architecture for Realistic Industrial Control System Honeypots
This is the repository containing source code for my Level 4 Project at the University of Glasgow, supervised by Dr. Shahid Raza. 

## File Structure
The project has 4 folders, each of which holds different components of SnapGAN. 

Firstly the **implementation** folder, contains the `proxy.py` file, `honeypot.py` file, both of which should be run in tandem to start a honeypot instance (on a virtual server, or otherwise). The `proxy.py` file contains customizable variables for the PLC name and serial number which should be altered to suit your use case. The .pkl file containing the trained synthesizer is included for testing purposes, but the idea is that it is replaced by a different generator trained on a dataset relating to the PLC intended to be emulated.

To train this generator, the **model_training** folder contains the required Jupyter Notebook- it is recommended this is executed in Colab, and trained on CPU. Any cells pertaining to the 'Electra' dataset can be removed and replaced; instead pass in a dataframe of 'address' and 'data' columns collected from your own dataset. Do note hyperparameters may need to be adjusted depending on the complexity of your dataset. The generator automatically saves to a .pkl file which can be swapped out in the honeypot.

The **test_scripts** folder contains basic response tests which can be ran against a running instance of SnapGAN to test its functionality.

The **log_analysis** folder contains a script used to analyze the `proxy.log` which will be generated once connections are made to your SnapGAN.

## Tech Stack
This project was completed entirely in Python.
Libraries: `sdv`, `pandas`, `python-snap7`

## Prerequisites
Python 3.12 or newer.

## Quick Start
Run `sudo python3 proxy.py` and `python3 honeypot.py` simultaneously to start up the honeypot. Connections will be possible once the Generator completes its first round of synthetic data point generation.
