sdk in c/c++ made for embedded systems, arduino.

general schemas of the lib:

+---------+  +---------+  +--------------+
|SECP256k1|  |Keccak256|  |insertion_sort|
+---------+  +---------+  +--------------+
     |           |               |
     |           |               |
     +-------+   |   +-----------+
             |   |   |
             |   |   |
           +-----------+  +--------+
           |AMB_Packing|  |Internet|
           +-----------+  +--------+ 
                 |            |
                 +------+ +---+
                        | |
                     +-------+
                     |AMB_api|
                     +-------+
