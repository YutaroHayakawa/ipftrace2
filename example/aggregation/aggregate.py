import sys
import json
import signal
import asyncio
from collections import defaultdict

#
# A simple example that reads ipftrace2 JSON stream (prduced by -o json),
# aggregates them per packet_id and prints similar output as -o aggregate
# for each seconds.
#


#
# Store that aggregates the samples per packet_id
#
# Key: packet_id string
# Val: List of Dict decorded from JSON
#
aggregation_store = defaultdict(list)


async def create_stdin_reader():
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    return reader


async def dump_aggregated_samples():
    while True:
        # Print aggregated results per second
        await asyncio.sleep(1)

        for packet_id, samples in aggregation_store.items():
            samples.sort(key=lambda sample: sample["timestamp"])
            print("===")
            for sample in samples:
                print("%u %03u %32.32s" % (sample["timestamp"],
                    sample["processor_id"], sample["function"]))

        # Clear after print to avoid unnecessary memory consumption
        aggregation_store.clear()


async def aggregate_samples():
    reader = await create_stdin_reader()
    while True:
        line = await reader.readline()
        sample = json.loads(line)
        packet_id = sample.pop("packet_id", None)
        aggregation_store[packet_id].append(sample)


async def main():
    loop = asyncio.get_event_loop()

    gather = asyncio.gather(
        dump_aggregated_samples(),
        aggregate_samples(),
    )

    loop.add_signal_handler(signal.SIGINT, lambda: gather.cancel())

    try:
        await gather
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    asyncio.run(main())
