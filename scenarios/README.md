# Artificial Tango

`artificial-tango.txt` choreographs traffic around the lyric sections embedded
in **Artificial Tango.mp3**: verse 1 uses NVIDIA MRC, verse 2 UET, and verse 3
Falcon. Choruses cycle all three protocols. All sections use 2 packets per
second for real-time animation, approximately matching the song’s 122 BPM.

Section timestamps are estimates; the MP3 has no timed lyrics. The configured
step durations total 183 whole seconds, rounding the 182.760-second track
length. Connection
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

The example uses a single destination, 1200-byte payloads, and 2 pps throughout. Use UDP encapsulation (`udp4` or `udp6`) because the script
includes MRC and Falcon. Change each line's rate or duration to tune the show.

To customize the steps, edit a copy of `artificial-tango.txt` and pass its path
to `--scenario` instead of the built-in name.

Scenario lines are differential: omitted parameters retain their values from
the CLI or the preceding steps. The built-in command supplies defaults of 2 pps and 1200-byte payloads before
CLI flags are applied. Set `--rate` and `--pkt-size` on the CLI to override them
for the entire song. When using the text file directly, supply those flags
explicitly to get the same animation defaults.
