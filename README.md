# Overwatch Shuffle Keys Replication
Overwatch 2 ShuffleKeys Replication POC

This won't work out of the box for everyone, since it doesn't handle every possible shuffle keys permutation correctly from my testing, but I have no use for it anymore, and haven't for nearly a year.
I tested it on the latest Overwatch 2 version as of today, which is 2.10.1.60211, but they'll be moving away from this in the future at some point, so I felt like I may as well share it.

I leave fixing it if your specific shufflekeys doesn't work as an exercise for you.

Please note that allocating an RWX region internally using a plain call to VirtualAlloc is likely a bad idea, but this is just a PoC. There is no real risk to doing this externally if you don't open a handle to the game, and just copy the function into your program's own RWX region and patch it within there, internally you'll likely want to be a bit more discrete.

Below is a general diagram with an analysis of what we have to patch.
![ShuffleKeys](https://github.com/Relyze/OverwatchShuffleKeys/assets/43044221/0cdb592f-d6bd-40d5-9e97-6bac4b2ef442)
