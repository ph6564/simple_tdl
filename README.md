# simple_tdl

these files are source codes for wireshark decoder for tactical data link and DIS simulation.
For windows32 add simple.dll in the wireshark plugin directory and you will be able to decode simple L11 Simple L16 and Simple DIS messages.
The DIS decoder has been adpated from the existing Dis decoder to work for encapsulated Dis messages in simple packets.
The Dll has been generated using visual studio.
This is an improvement of previous Link 16 decoder  that can't be used  in simple.

The decoders just show messages names and partially decode the contents of the messages.




