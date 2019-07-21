package config
import (
    "testing"
    "fmt"
)

func TestConfig(t *testing.T) {
    cfg := NewConfig("test", "0.0.1")
    if val := cfg.Get("maxchannels"); val != nil {
        fmt.Printf("config[maxchannels]=%v\n",val)
    } else{
        fmt.Printf("error: config[maxchannels] not found\n")
    }
    if val := cfg.Get("nonexist"); val != nil {
        fmt.Printf("config[nonexist]=%v\n", val)
        t.Errorf("config parser is broken")
    } else{
        fmt.Printf("error: config[nonexist] not found\n")
    }

    args := [...]string{"--daemon", "--address", "example.com"}
    cfg.Parse(args[:])
    //check if  default values can be checked
    if cfg.IsSet("daemon") {
        fmt.Println("daemon is set!")
    } else {
        fmt.Println("daemon is not set")
        t.Errorf("daemon should default to false; want false")
    }
    if cfg.IsSet("address") {
        add := cfg.Get("address")
        if add.String() != "example.com" {
            t.Errorf("address should be \"example.com\"; have %v", add.String())
        }
        fmt.Printf("address is set! %s\n", add.String())
    } else {
        t.Errorf("address should be set; want localhost")
    }

    cfg.Flags.Bool("default_enabled", true, "testing if bool flags can be checked")
    if cfg.IsSet("default_enabled") {
        fmt.Println("default value determined OK")
    }
}
