# Traffic Manipulator

## Introduction 

This is a traffic mutation tool employing Particle Swarm Optimization (__PSO__) algorithm. Given an _original (malicious) network traffic set_ and a _target feature set_, this tool can generate a *new mutated network traffic set* that **its features extracted by a specific extractor will be as similar as possible to the target feature set**.

## Implementation Notes

- Special Python dependencies:  cython and scapy
- The source code has been tested with Python 3.6 on a Linux 64bit and Win10  64bit machine 

## Structure

``` 
- AfExtractor
	- ...
	- ...
```

This is the implementation of [AfterImage]( https://github.com/ymirsky/Kitsune-py ), the feature extractor used in Kitsune.

``` 
- manipulator.py
- ...
- ...
- main.py
```

These are the implementation of our mutation strategy. Regardless of details, you can use `main.py` as an interface to mutate network traffic.

 ## Usage

1. First, compiling cython file in AfterImage as follows:

   ```
   cd AfExtractor/
   python setup.py build_ext --inplace
   ```

2. Using `main.py` to mutate your traffic. Note that, some required arguments can be give as the following example:

   ```
   python main.py -m ./example/test.pcap -b ./example/mimic_set.csv
   ```

   - `-m` the original (malicious) network traffic set (".pcap" format)
   - `-b` the target feature set (".csv" format)

   Other parameters all have default value, use  `python main.py -h` or `python manipulator.py -h` for more details. 

3. **Parameters**:

   See line 24 in `main.py` :

   ``` python
   # Choose Params
   m.change_particle_params(w=0.6,c1=0.7,c2=1.4)
   m.change_pso_params(max_iter=5,particle_num=10,grp_size=5)
   m.change_manipulator_params(grp_size=5,
                               min_time_extend=0.,
                               max_time_extend=5.,
                               max_cft_pkt=4,
                               max_crafted_pkt_prob=0.3)
   ```

   There are basically 9 parameters in our algorithm, which can be divided into 3 groups:

   - Internal parameters in PSO (in terms of velocity update):
     1. `w` : wight of inertia 
     2. `c1`: wight of cognitive force 
     3. `c2`: wight of social force 

   - Internal parameters in PSO  (in terms of searching configuration): 
     4. `max_iter`: iterations of searching 
     5. `particle_num`: total number of particles (population)
     6. `grp_size`: number of particles per neighborhood

    -  manipulator parameters :
       7. `grp_size`: number of network packets mutated for each processing (Notice it's different from the above `grp_size`)
       8. `max_time_extend`: the interarrival time of each two mutated packets in mutated traffic is no more than `max_time_extend` times original interarrival time. 
       9. `max_cft_pkt`: the maximum number of crafted packets aggregated with one original packet.

   **Simply, if you wish higher performance, increase Param 4,5,6 and 8, 9 gracefully. And if you wish to speed up results, decrease Param 4,5,6.**

## Memo

To execute `Traffic Manipulator` on a large traffic set can be overnight work... Suggestions on saving time can be changing internal parameters in PSO (e.g., decreasing the population size or iteration numbers)  OR just choosing another efficient feature extractor (AfterImage is exactly the performance bottleneck now).