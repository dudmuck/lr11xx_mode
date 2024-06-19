
  # LR11x operating mode parser for [salae](https://www.saleae.com)
Shows time duration spent in operating modes of the radio. 
Use this simultaneous with [LR11xx command parser](https://github.com/dudmuck/saleae_lr11xx) in order to see both opcodes sent to radio along with the operating mode the radio.
  
## hookup
SPI pins required: SCLK, MISO, MOSI, nSS, and highly suggested to connect the interrupt DIO9 (or DIO11) pin and BUSY pin.
