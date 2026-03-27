## Model Training
- Donwload the dataset (http://perception.inf.um.es/ICS-datasets/), and split into files of ~5000 rows using `split -l 5000 electra.csv split_`. (https://www.geeksforgeeks.org/linux-unix/split-command-in-linux-with-examples/)

The intention is that SnapGAN runs on whichever PLC's data is provided to closely emulate an exact PLC. Feel free to replace the Electra dataset with your own by deleting relevant cells in `ctgan.ipynb`. The dataset format is addresses (integers), and data (integers).

This was done in Google Colaboratory, so the corresponding requirements.txt file contains Google Colaboratory dependencies, and therefore should only be installed if recreating the environment. 

- Replace the calls to os.changedir() with whatever directory changes required to get to the directory above the split dataset.

- Run all cells of the notebook (replace pip install with recursive install of requirements.txt if using Google Colab)

## Proxy

- Create a python venv by running `python3 -m venv venv`
- Download dependencies using requirements.txt file in respective directory.
- Run a tmux session using `tmux new-session -d -s proxy`
- Enter tmux session using `tmux attach -t proxy`
- Activate virtual environment: `source venv/bin/activate`
- Run `sudo python3 proxy.py`. Sudo is required as Port 102 is non-standard.

## Honeypot

- Create a python venv by running `python3 -m venv venv`
- Download dependencies using requirements.txt file in respective directory.
- Run a tmux session using `tmux new-session -d -s honeypot`
- Enter tmux session using `tmux attach -t honeypot`
- Activate virtual environment: `source venv/bin/activate`
- Run `python3 honeypot.py`. Do this only after running the proxy. 

If this is being run on a deployed instance, wait until the generated values have finished loading (check output in tmux session), and only then open Port 102 to the public internet.

## Analyze Honeypot Logs 

Honeypot logs will be stored to honeypot.log, and proxy logs will be stored to proxy.log. To analyze the proxy logs to observe IP address patterns, run `python analyze_connections_proxy.py <logfile>`.

## Run Test Scripts

The test scripts used in the evaluation can be run both locally and targetted towards a deployed instance. The package requirements for these scripts can be downloaded via the requirements.txt.

To run the basic_function_code_tests.py, simply replace the PLC_IP on line 4 with your target IP, and run `python3 basic_function_code_test.py`.

To run further_functions.py, run `python3 further_functions.py --host 127.0.0.1`. Replace host ip with target ip.
