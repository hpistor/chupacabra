# rm -rf ranges/* && swipl prolog/main.pl createMachineRanges '2' '[[(0, [1]), (1, [])], [(0, []), (1, [])]]'
rm -rf ranges/* && python generateRanges.py
