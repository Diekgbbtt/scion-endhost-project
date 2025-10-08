package lib

type TestState string

const (
	TestNotStarted TestState = "TestNotStarted"
	TestRunning    TestState = "TestRunning"
	TestPassed     TestState = "TestPassed"
	TestFailed     TestState = "TestFailed"
)

type TestID int

const (
	BasicConnectivityTest               TestID = 01
	BasicMultipathTest                  TestID = 02
	MinimizeCarbonIntensity             TestID = 10
	MaximizeBandwidthWithBoundedLatency TestID = 11
	EpicHiddenPathTest                  TestID = 20
	FabridConnectivityTest              TestID = 30
	FabridPolicy1Test                   TestID = 31
	FabridPolicy2Test                   TestID = 32
	FabridPolicy3Test                   TestID = 33
	ASFinderTest                        TestID = 40
)

type Test struct {
	ID      TestID `json:"ID"`
	Payload any    `json:"Payload"`
}

type TestResult struct {
	ID      TestID    `json:"ID"`
	Payload any       `json:"Payload"`
	State   TestState `json:"State"`
}
