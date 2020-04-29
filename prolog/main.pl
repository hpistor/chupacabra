:- (initialization main).
:- [alpaca].

/**
 * Run as:  swipl prolog/main.pl <predicateName> <args>
 * 
 * examples:
 *      graphAllVulns 'filename.dot'
 *      createRangeFromIGS '[Goal]' '[InitialState]' '[Params]'
 */
main :-
    current_prolog_flag(argv, Argv),
    parseArgs(Argv),
    halt(0).
main :-
    halt(1).

% Used for createRangeFromIGS
parseArgs([Pred|Rest]) :-
    argsToTerm(Rest, Goal, Initial, Params),
    current_predicate(Pred/3),
    Run=..[Pred, Goal, Initial, Params],
    call(Run).

parseArgs([Pred | Rest]) :-
    argsToTerm(Rest, MachineCount),
    current_predicate(Pred/1),
    Run=..[Pred, MachineCount],
    call(Run).

argsToTerm([ArgsMachine], MachineCount) :-
    term_to_atom(MachineCount, ArgsMachine).


argsToTerm([ArgsGoal, ArgsInitial, ArgsParams], Goal, Initial, Params) :-
    term_to_atom(Goal, ArgsGoal),
    term_to_atom(Initial, ArgsInitial),
    term_to_atom(Params, ArgsParams).

