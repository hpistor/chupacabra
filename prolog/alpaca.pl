:- [configs].
:- [graphviz].
:- [output].
:- [analysis].
:- [vulnDatabase].

:- use_module(library(uuid)).

% Example: createRangeFromIGS(['server_access_root'], [], 'server_access_root')
% Finds all lattices, create directories, generate lattices in directory, create ansible playbooks
% testprint([], FinalVulnGroups, FinalVulnGroups).


% testprint([Path | Paths], VulnGroups, FinalVulnGroups) :-
%     printtuple(Path), nl,
%     testprint(Paths, VulnGroups, FinalVulnGroups).

% printtuple([], VulnGroup, VulnGroup).
% printtuple([(A, B, C) | Rest]) :-
%     print(A), print(" -> "), print(C), print(" via "), print(B), nl, printtuple(Rest).

assertVulnGroups(_, _, []).
assertVulnGroups(Initial, Goal, [Lattice | Lattices]) :-
    assertz(vulngroup(Initial, Goal, Lattice)),
    assertVulnGroups(Initial, Goal, Lattices).


% Find all vulnerability groups that go from [] -> [root_shell]
findAllVulnGroups() :-
    setof([(Config, Vulns)], achieveGoal([root_shell], [], [], Config, Vulns), Paths),
    groupPathsByConfigs(Paths, LatticePaths),
    maplist(appendPathsIntoLattice, LatticePaths, Lattices),
    assertVulnGroups([] , [root_shell], Lattices).

generateListFromOneToN(1, [1]).
generateListFromOneToN(N, [N | T]) :-
    N > 1,
    N1 is N-1,
    generateListFromOneToN(N1, T).

createMachineRanges(MachineCount, ListOfListofConnections) :-
    findAllVulnGroups(),
    uuid(RangeId, [version(4)]),
    format("Creating range ~s~n", [RangeId]),
    format(atom(RangeDirRel), "./ranges/~s", [RangeId]),
    absolute_file_name(RangeDirRel, RangeDir),
    make_directory_path(RangeDir),
    findall((PermutationId, Permutation),
            ( member(Permutation, ListOfListofConnections),
              uuid(PermutationId, [version(4)])
            ),
            PermutationsWithId),   
    maplist(createPermutation(RangeDir, RangeId, MachineCount), PermutationsWithId).
    % createMachines(2, [[(0, [1]), (1, [])], ])
    % each lattice is one permutation of connections
    % Create ranges/range/lattice
    % create ranges/range/lattice/machine_one & provision
    % repeat for machine count

createPermutation(RangeDir, RangeId, MachineCount, (PermutationId, Permutation)) :-
    format("Creating permutation ~s in range ~s~n", [PermutationId, RangeId]),
    format(atom(LatticeDir), "~s/~s", [RangeDir, PermutationId]), nl,
    make_directory_path(LatticeDir),
    format(atom(PermutationTerraformScript), "~s/terraform.py", [LatticeDir]),
    format(atom(LatticeProvisionScript), "~s/provision.sh", [LatticeDir]),
    absolute_file_name("./provision.sh", ProvisionScript),
    absolute_file_name("./terraform.py", TerraformScript),
    link_file(ProvisionScript, LatticeProvisionScript, symbolic),
    link_file(TerraformScript, PermutationTerraformScript, symbolic),
    createMachines(LatticeDir, MachineCount, (PermutationId, Permutation)).

testprint([H | T]) :-
    print(H), nl, nl, testprint(T).

assignLattices(MachineCount, FinalLattices) :-
    findall(X, vulngroup(_, _, X), AllVulnGroups),
    assignLatticesStep(0, MachineCount, AllVulnGroups, [], FinalLattices).


assignLatticesStep(Machine, Machine, _, FinalLattices, FinalLattices).

assignLatticesStep(CurrentMachine, MachineCount, AllVulnGroups, AssignedLattices, FinalLattices) :-
    random_member(Lattice, AllVulnGroups),
    realizeLatticeConfigsFromParams([Lattice], [paramPasswordLength-5], [RealizedLattice]),
    NextMachine is CurrentMachine + 1,
    CurrentMachine < MachineCount,
    assignLatticesStep(NextMachine, MachineCount, AllVulnGroups, [(CurrentMachine, RealizedLattice) | AssignedLattices], FinalLattices).

% realizeLatticeConfigsFromParams([(Config, Vulns)|Rest], Params, [(RealizedConfig, Vulns)|RealizedRest]) :-
%     realizeConfigFromParams(Config, Params, RealizedConfig),
%     realizeLatticeConfigsFromParams(Rest, Params, RealizedRest).

outputLattices(_, [], _).

outputLattices(LatticesDir, [(MachineNum, Lattice) | T], PermutationId) :-
    format(atom(MachineDirectory), "~s/machine_~d", [LatticesDir, MachineNum]),
    make_directory_path(MachineDirectory),
    generatePNGFromLattice(MachineDirectory, Lattice),
    Lattice = (Configs, _),
    format(atom(MachineId), "~s_~d", [PermutationId, MachineNum]),
    createTerraformFiles(MachineId, MachineDirectory),
    createYamlFiles(Configs, MachineDirectory), !,
    outputLattices(LatticesDir, T, PermutationId).
    
writeListToFile(List, File) :- open(File, write, Stream),
                   \+ writeListToStream(Stream, List),
                   close(Stream).

writeListToStream(Stream, List) :- member(Element, List),
                   write(Stream, Element),
                   write(Stream, '\n'),
                   fail.

createMachines(LatticeDir, MachineCount, (PermutationId, Permutation)) :-
    assignLattices(MachineCount, FinalLattices), !,
    outputLattices(LatticeDir, FinalLattices, PermutationId),
    format(atom(ConnectionListFile), "~s/connections.txt", [LatticeDir]),
    writeListToFile(Permutation, ConnectionListFile)
    .






createRangeFromIGS(InitialState, Goal, Params) :-
    createAllLatticesFromIGS(InitialState, Goal, Lattices),
    % realize lattice config if there are predicates involved
    realizeLatticeConfigsFromParams(Lattices, Params, RealizedLattices),
    outputRange(InitialState, Goal, Params, RealizedLattices).


realizeLatticeConfigsFromParams([], _, []).
realizeLatticeConfigsFromParams([(Config, Vulns)|Rest], Params, [(RealizedConfig, Vulns)|RealizedRest]) :-
    realizeConfigFromParams(Config, Params, RealizedConfig),
    realizeLatticeConfigsFromParams(Rest, Params, RealizedRest).


% e.g., createAllLatticesFromIGS([server_access_root], [], Lattices)
% paths will be in reverse usually, but that doesnt matter for generating a lattice
% result (Lattices) will have structure: [Lattice|...],
% where each Lattice has the structure: (Config, Vulns),
% where Config is a maximally merged config for the lattice (all paths in the
% lattice are compatible with this same maximal config)
createAllLatticesFromIGS(InitialState, Goals, Lattices) :-
    setof([(Config, Vulns)], achieveGoal(Goals, InitialState, [], Config, Vulns), Paths),
    % repeatedly merge these configs until no more merging is possible
    groupPathsByConfigs(Paths, LatticePaths),
    % now keep just one config and all paths, per lattice
    maplist(appendPathsIntoLattice, LatticePaths, Lattices)
    .

% keep single config (all paths will share this same config), append all paths into a set of vulns
appendPathsIntoLattice([], []).
appendPathsIntoLattice([(Config, Vulns)|Rest], (Config, AllVulns)) :-
    maplist(secondPair, Rest, RestVulns),
    append([Vulns|RestVulns], AllVulns).

secondPair((_, B), B).

% work backwards from goal to initial
achieveGoal([], _, [], [], []).
achieveGoal([Goal|Goals], InitialState, StartingConfigs, AcceptedConfigs, [(Input, Description, Output)|Vulns]) :-
    vuln(Description, Input, Output, Configs),
    member(Goal, Output),
    subtract(Input, InitialState, NewInput),
    union(NewInput, Goals, NewGoals),
    union(InitialState, Output, NewState),
    % print("-----------"), nl ,
	format(atom(PrintGoal), "Goal: ~s", [Goal]),
    atomic_list_concat(Goals, ", ", GoalsAtom), atom_string(GoalsAtom, GoalsString),
    format(atom(PrintGoals), "Goals: ~s", [GoalsString]),
    atomic_list_concat(InitialState, ", ", InitialStateAtom), atom_string(InitialStateAtom, InitialStateString),
    format(atom(PrintInitialState), "InitialState: ~s", [InitialStateString]),
    atomic_list_concat(StartingConfigs, ", ", StartingConfigsAtom), atom_string(StartingConfigsAtom, StartingConfigsString),
    format(atom(PrintStartingConfigs), "StartingConfigs: ~s", [StartingConfigsString]),
    atomic_list_concat(Input, ", ", InputAtom), atom_string(InputAtom, InputString),
    format(atom(PrintInput), "Input: ~s", [InputString]),
    atomic_list_concat(Output, ", ", OutputAtom), atom_string(OutputAtom, OutputString),
    format(atom(PrintOutput), "Output: ~s", [OutputString]),
    format(atom(PrintDescription), "Description: ~s", [Description]),
    % print(PrintGoal), nl, print(PrintGoals), nl, print(PrintInitialState), nl, print(PrintStartingConfigs), nl, print(PrintInput), nl, print(PrintDescription), nl, print(PrintOutput), nl, print(Vulns), nl,
    % print("-----------"), nl,
    achieveGoal(NewGoals, NewState, StartingConfigs, NewConfigs, Vulns),
    checkConfigs(NewConfigs, Configs, AcceptedConfigs)
    .

