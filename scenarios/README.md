# Artificial Tango

`artificial-tango.txt` choreographs traffic around the lyric sections embedded
in **Artificial Tango.mp3**: verse 1 uses NVIDIA MRC, verse 2 UET, and verse 3
Falcon. Choruses cycle all three protocols. Rates soften for the bridge and
spoken outro.

Section timestamps are estimates; the MP3 has no timed lyrics. The configured
step durations total 182.760 seconds, matching the file duration, but connection
setup and reliable-window draining add playback time. This is a traffic script;
it does not play or synchronize the audio.

Start a receiver on the destination host:

```sh
sudo sitg --role recv --iface eth1 --proto all --encap udp4 --duration 0s
```

The scenario is embedded in the binary. Run on the sender, replacing the interface and
destination address with those of your lab:

```sh
sudo sitg --scenario artificial-tango \
  --iface eth1 --encap udp4 --dst 192.0.2.2
```

The example uses a single destination, 1200-byte payloads, and modest packet
rates (100–5000 pps). Use UDP encapsulation (`udp4` or `udp6`) because the script
includes MRC and Falcon. Change each line's rate or duration to tune the show.

To customize the steps, edit a copy of `artificial-tango.txt` and pass its path
to `--scenario` instead of the built-in name.
