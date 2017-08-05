# simple_tdl
tactical data link and civilian data link 
these filesare source codes for wireshark decoder.
For windows32 add simmple.dll in the wireshark plugin directory and you will be able to decode simple L11 Simple L16 and Simple DIS messages.
The DIS decoder hasbeen adpated from the existing Dis decoder to work for encapsulated Dis messages in simple packets.
The Dll has been generated using visual studio.
Link 16 decoders has been improved  from a Link 16 decoderthat can't be used alone in Wireshark.

The decoders just show messages names and partially decode the contents of the messages.

Full uncoding is feasible but actually my decoder is too slow to be used within wireshark.




