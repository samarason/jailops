//go:build race

package server_test

// raceEnabled shrinks the request matrices: the race detector makes every request several times slower.
const raceEnabled = true
