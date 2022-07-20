--------------------------------------------------------------------------------
--! @file       ti_tinyjambu_control.vhd
--! @brief      A threshold implementation protected TinyJAMBU controller
--! @author     Sammy Lin
--! @copyright  Copyright (c) 2020 Cryptographic Engineering Research Group
--!             ECE Department, George Mason University Fairfax, VA, U.S.A.
--!             All rights Reserved.
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt
--! @note       This is publicly available encryption source code that falls
--!             under the License Exception TSU (Technology and software-
--!             unrestricted)
--------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

library work;
use work.design_pkg.all;
use work.NIST_LWAPI_pkg.all;

entity tinyjambu_control is
    port (
        clk             : in std_logic;
        reset           : in std_logic;
        decrypt_in      : in std_logic;
        -- Datapath control signals
        key_index       : out std_logic_vector      (1          downto 0);
        key_load        : out std_logic;
        d_index         : out std_logic_vector      (1          downto 0);
        d_load          : out std_logic;
        decrypt_out     : out std_logic;
        nlfsr_reset     : out std_logic;
        nlfsr_en        : out std_logic;
        nlfsr_load      : out std_logic;
        partial         : out std_logic;
        bdo_sel         : out std_logic;
        fbits_sel       : out std_logic_vector      (1          downto 0);
        s_sel           : out std_logic_vector      (1          downto 0);
        partial_bytes   : out std_logic_vector      (1          downto 0);
        -- CryptoCore Control Signals
        key             : in std_logic_vector       (CCSW-1     downto 0);
        key_valid       : in std_logic;
        key_update      : in std_logic;
        key_ready       : out std_logic;
        bdi_valid       : in std_logic;
        bdi_a           : in std_logic_vector       (CCW-1      downto 0);
        bdi_b           : in std_logic_vector       (CCW-1      downto 0);
        bdi_c           : in std_logic_vector       (CCW-1      downto 0);
        bdi_ready       : out std_logic;
        bdi_pad_loc     : in std_logic_vector       (CCWdiv8-1  downto 0);
        bdi_valid_bytes : in std_logic_vector       (CCWdiv8-1  downto 0);
        bdi_size        : in std_logic_vector       (3      -1  downto 0);
        bdi_eoi         : in std_logic;
        bdi_eot         : in std_logic;
        bdi_type        : in std_logic_vector       (3          downto 0);
        bdo_a           : in std_logic_vector       (CCW-1      downto 0);
        bdo_b           : in std_logic_vector       (CCW-1      downto 0);
        bdo_c           : in std_logic_vector       (CCW-1      downto 0);
        bdo_type        : out std_logic_vector      (3          downto 0);
        bdo_ready       : in std_logic;
        bdo_valid       : out std_logic;
        bdo_valid_bytes : out std_logic_vector      (CCWdiv8-1  downto 0);
        end_of_block    : out std_logic;
        hash_in         : in std_logic;
        m               : in std_logic_vector       (RW - 1 downto 0); -- Random input

        msg_auth_ready  : in  std_logic;
        msg_auth_valid  : out std_logic;
        msg_auth        : out std_logic

    );
end entity tinyjambu_control;

architecture behavioral of tinyjambu_control is

-- Keep architecture ---------------------------------------------------------
attribute keep_hierarchy : string;
attribute keep_hierarchy of behavioral: architecture is "true";

-- Constants for the number of permutations
constant P_KEYSETUP     : natural := 1024   /CONCURRENT;
constant P_NPUBSETUP    : natural := 384    /CONCURRENT;
constant P_AD           : natural := 384    /CONCURRENT;
constant P_ENCRYPT      : natural := 1024   /CONCURRENT;
constant P_TAG_1        : natural := 1024   /CONCURRENT;
constant P_TAG_2        : natural := 384    /CONCURRENT;
constant NUM_KEY_WORDS  : natural := 4;

-- CryptoCore States
type state_type is (IDLE, 
-- Load and process the key
LOAD_KEY, KEY_INIT,
-- Process the nonce
NPUB_INIT_A,NPUB_INIT_B,NPUB_INIT_C,
-- Load and process the associated data
WAIT_AD, AD_A, AD_B, AD_C, 
-- Process plaintext/ciphertext
ENCRYPT_A, ENCRYPT_B, ENCRYPT_C,
-- Generate the 64 bit tag
TAG_A, TAG_B, TAG_C,
TAG_D, TAG_E, TAG_F);

signal state            : state_type := IDLE;
signal next_state       : state_type := IDLE;

signal key_count        : unsigned (2 downto 0);
signal next_key_count   : unsigned (2 downto 0);

signal cycles           : unsigned (10 downto 0);
signal next_cycles      : unsigned (10 downto 0);

signal npub             : unsigned (1 downto 0);
signal next_npub        : unsigned (1 downto 0);

-- Keep signals -----------------------------------------------
attribute keep : string;

attribute keep of state            : signal is "true";
attribute keep of next_state       : signal is "true";

attribute keep of key_count        : signal is "true";
attribute keep of next_key_count   : signal is "true";

attribute keep of cycles           : signal is "true";
attribute keep of next_cycles      : signal is "true";

attribute keep of npub             : signal is "true";
attribute keep of next_npub        : signal is "true";

begin
key_index               <= std_logic_vector (key_count(1 downto 0));
 
    process(clk)
    begin
        if rising_edge(clk) then
            if (reset = '1') then
                state       <= IDLE;
                npub        <= (others => '0');
                key_count   <= (others => '0');
                cycles      <= (others => '0');
                
            else
                state       <= next_state;
                npub        <= next_npub;
                key_count   <= next_key_count;
                cycles      <= next_cycles;
                
            end if;
        end if;
    end process;
    
    process(state, key_valid, key_update, key_count,
            bdi_valid, bdi_eoi, bdi_eot, cycles,
            bdo_ready, key, msg_auth_ready)
        begin
        -- Default values
        nlfsr_en            <= '0';
        nlfsr_reset         <= '0';
        nlfsr_load          <= '0'; 
        decrypt_out         <= '0';
        key_load            <= '0';
        key_ready           <= '0';
        bdi_ready           <= '0';
        bdo_valid           <= '0';
        end_of_block        <= '0';
        d_load              <= '0';
        partial             <= '0';
        bdo_sel             <= '0';
        msg_auth_valid      <= '0';
        msg_auth            <= '0';
               
        bdo_type            <= (others => '0');
        bdo_valid_bytes     <= (others => '0');
        s_sel               <= (others => '1');
        fbits_sel           <= (others => '0');
        partial_bytes       <= (others => '0');
        next_key_count      <= (others => '0');
        next_npub           <= (others => '0');
        next_cycles         <= (others => '0');

        next_state          <= state;
        
        case state is 
        when IDLE => 
            --bdi_ready       <= '1';
            s_sel           <= b"11";
            nlfsr_reset     <= '1';
            if (key_valid = '1' and key_update = '1') then
                next_state  <= LOAD_KEY;
            end if;
        when LOAD_KEY =>
            key_ready       <= '1';
            next_key_count  <= key_count;
            if (key_valid = '1') then
                key_load    <= '1';
                next_key_count  <= key_count + 1;
                if ((key_count + 1) >= NUM_KEY_WORDS) then
                    next_state <= KEY_INIT;
                end if;
            end if;
        when KEY_INIT =>
            nlfsr_en        <= '1';
            next_cycles     <= cycles + 1;
            if (cycles + 1 >= P_KEYSETUP) then
                next_state   <= NPUB_INIT_A;
            end if;
        when NPUB_INIT_A =>
            fbits_sel       <= b"00";
            s_sel           <= b"00";
            nlfsr_load      <= '1';
            next_state      <= NPUB_INIT_B;
            next_npub       <= npub;
        when NPUB_INIT_B =>
            nlfsr_en        <= '1';
            next_cycles     <= cycles + 1;
            next_npub       <= npub;
            if (cycles + 1 >= P_NPUBSETUP) then
                next_state   <= NPUB_INIT_C;
            end if;
        when NPUB_INIT_C =>
            s_sel           <= b"01";
            next_npub       <= npub;
            if (bdi_valid = '1') then
                bdi_ready   <= '1';
                nlfsr_load  <= '1';
                if (npub >= 2) then
                    next_state  <= WAIT_AD;
                else
                    next_npub   <= npub + 1;
                    next_state  <= NPUB_INIT_A;
                end if;
                if (bdi_eoi = '1') then
                    next_state  <= TAG_A;
                end if;
            end if;
        when WAIT_AD =>
            if (bdi_valid = '1') then
                if (bdi_type = HDR_AD) then
                    next_state  <= AD_A;
                else
                    next_state  <= ENCRYPT_A;
                end if;
            end if;
        when AD_A => 
            fbits_sel       <= b"01";
            s_sel           <= b"00";
            nlfsr_load      <= '1'; 
            next_state      <= AD_B;
        when AD_B => 
            nlfsr_en        <= '1';
            next_cycles     <= cycles + 1;
            if (cycles + 1 >= P_AD) then
                next_state  <= AD_C;
            end if;
        when AD_C => 
            bdi_ready   <= '1';
            if (bdi_valid = '1') then
                s_sel       <= b"01";
                nlfsr_load  <= '1';
                if (bdi_eot = '1') then
                    if (bdi_eoi = '1') then
                        next_state          <= TAG_A;
                    else
                        next_state          <= ENCRYPT_A;
                    end if;
                    if (bdi_valid_bytes = b"0000") then
                        nlfsr_load      <= '0';
                    else
                        partial         <= '1'; 
                        partial_bytes   <= bdi_size(1 downto 0);
                    end if;
                else
                    next_state          <= AD_A;
                end if;    
            end if;
        when ENCRYPT_A =>
            fbits_sel       <= b"10";
            s_sel           <= b"00";
            nlfsr_load      <= '1'; 
            next_state      <= ENCRYPT_B;
        when ENCRYPT_B =>
            nlfsr_en        <= '1';
            next_cycles     <= cycles + 1;
            if (cycles + 1 >= P_ENCRYPT) then
                next_state  <= ENCRYPT_C;
            end if;
        when ENCRYPT_C =>
            bdi_ready       <= '1';
            if (bdi_valid = '1') then
                s_sel       <= b"01";
                bdo_valid   <= '1';
                bdo_valid_bytes <= bdi_valid_bytes;
                nlfsr_load  <= '1'; 
                if (decrypt_in = '1') then
                    bdo_type    <= HDR_PT;
                    decrypt_out <= '1';
                else
                    bdo_type    <= HDR_CT;
                end if;
                if (bdi_eot = '1') then
                    end_of_block <= '1';
                    next_state  <= TAG_A;
                    if (bdi_valid_bytes = b"0000") then
                        nlfsr_load      <= '0';
                    else
                        partial         <= '1'; 
                        partial_bytes   <= bdi_size(1 downto 0);
                    end if;
                else
                    next_state  <= ENCRYPT_A;
                end if;
            end if;
        when TAG_A =>
            fbits_sel       <= b"11";
            s_sel           <= b"00";
            nlfsr_load      <= '1'; 
            next_state      <= TAG_B;
        when TAG_B =>
            nlfsr_en        <= '1';
            next_cycles     <= cycles + 1;
            if (cycles + 1 >= P_TAG_1) then
                next_state  <= TAG_C;
            end if;
        when TAG_C =>
            bdo_type        <= HDR_TAG;
            bdo_valid       <= '1';
            bdo_valid_bytes <= (others => '1');
            bdo_sel         <= '1';
            if (bdo_ready = '1') then
                next_state  <= TAG_D;
            end if;
            -- Tag verification
            if (decrypt_in = '1') then
                bdi_ready   <= '1';
                next_state  <= TAG_D;               
            end if;
        when TAG_D =>
            fbits_sel       <= b"11";
            s_sel           <= b"00";
            nlfsr_load      <= '1'; 
            next_state      <= TAG_E;
        when TAG_E =>
            nlfsr_en        <= '1';
            next_cycles     <= cycles + 1;
            if (cycles + 1 >= P_TAG_2) then
                next_state  <= TAG_F;
            end if;
        when TAG_F =>
            bdo_type        <= HDR_TAG;
            bdo_valid       <= '1';
            bdo_valid_bytes <= (others => '1');
            bdo_sel         <= '1';
            end_of_block    <= '1';
            if (bdo_ready   <= '1') then
                next_state  <= IDLE;
            end if;
            if (decrypt_in = '1') then
                bdi_ready       <= '1';
                msg_auth        <= '1';
                msg_auth_valid  <= '1';
                if (msg_auth_ready = '1') then
                    next_state  <= IDLE;
                end if;
            end if;
        when others =>
            next_state      <= IDLE;
        end case;
    end process;
end architecture behavioral;

