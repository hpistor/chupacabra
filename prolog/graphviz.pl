
% Create master graph of all vulnerabilities; does not relate to any specific lattice.
graphAllVulns(FileName) :-
	findall((Prereqs, Vuln, Result), vuln(Vuln, Prereqs, Result, _), AllVulns),
	formatDotVulns(AllVulns, Str),
	generatePNGFromDot(Str, FileName), !.

generatePNGFromLatticeWithNum(LatticeDir, (Configs, Vulns)) :-
	formatVulnsForGraphviz(Vulns, Final),
	print(2),
	formatDotVulns(Final, Str),
	print(3),
	format(atom(DotFilename), "~s/lattice", [LatticeDir]),
	print(4),
	generatePNGFromDot(Str, DotFilename),
	print(5).


formatVulnsForGraphviz(Vulns, Final) :-
	formatVulnsForGraphvizStep(Vulns, [], Final).

formatVulnsForGraphvizStep([], FinalPath, FinalPath).

formatVulnsForGraphvizStep([(Input, Name, Output, _) | T], BuildPath, FinalPath) :-
	formatVulnsForGraphvizStep(T, [(Input, Name, Output) | BuildPath], FinalPath).

generatePNGFromLattice(LatticeDir, (_, Vulns)) :-
	print(1), 
	formatDotVulns(Vulns, Str),
	print(2), 
	format(atom(DotFilename), "~s/lattice", [LatticeDir]),
	print(3), 
	generatePNGFromDot(Str, DotFilename).

generatePNGFromDot(String, File) :-
	format(atom(FileGv), "~s.gv", [File]),
	open(FileGv, write, Stream),
	writeln(Stream, "strict digraph \"Vulnerability Lattice\" {"),
	write(Stream, String),
	write(Stream, "}"),
	close(Stream),
	format(atom(Command), "dot -Tpng ~s.gv > ~s.png", [File, File]),
	shell(Command).

formatDotSingleVuln(_, [], "").
formatDotSingleVuln(VulnID, [(Prereq, Vuln, Result)|Rest], String) :-
	formatDotSingleVuln(VulnID, Rest, String1),
    ( Prereq = none -> format(atom(PrereqID), "PRE~a", [VulnID]), PrereqLabel = '' ; PrereqLabel = Prereq, PrereqID = Prereq ),
    format(atom(String), "~s\"~a\" [shape=\"none\", label=\"~a\"];~n\"~a\" [shape=\"none\"];~n\"~s\" [shape=\"box\", label=\"~a\"];~n\"~a\" -> \"~s\";~n\"~s\" -> \"~a\";~n", [String1, PrereqID, PrereqLabel, Result, VulnID, Vuln, PrereqID, VulnID, VulnID, Result]).

formatDotVulns([], "").
formatDotVulns([(Prereqs, Vuln, Result)|Rest], Str) :-
    % if prereqs are empty, put in a dummy [none] so that makeTripletsFromListAtomList below doesnt ignore the vuln
    ( Prereqs = [] -> makeTripletsFromListAtomList([none], Vuln, Result, [], Out) ; makeTripletsFromListAtomList(Prereqs, Vuln, Result, [], Out) ),
    format(atom(VulnID), "~k~a~k", [Prereqs, Vuln, Result]),
	formatDotSingleVuln(VulnID, Out, Str1),
	formatDotVulns(Rest, Str2),
	format(atom(Str), "~s~s", [Str1, Str2]).

makeTripletsFromListAtomList([], _, Results, Pairs, Out) :- addAtomIdToEndOfEachPair(Results, Pairs, Out).
makeTripletsFromListAtomList([H|T], Vuln, Results, Rest, Out) :-
	makeTripletsFromListAtomList(T, Vuln, Results, [(H, Vuln)|Rest], Out).

addAtomIdToEndOfEachPair([H|T], Pairs, Out) :-
	addAtomToEndOfEachPair(H, Pairs, Out1),
	addAtomIdToEndOfEachPair(T, Pairs, Out2),
	append(Out1, Out2, Out).
addAtomIdToEndOfEachPair([], _, []).

addAtomToEndOfEachPair(Res, [(A,B)|T], [(A, B, Res)|Rest]) :-
	addAtomToEndOfEachPair(Res, T, Rest).
addAtomToEndOfEachPair(_, [], []).

