--------------------------------------------------------------------------------
--! @file       CryptoCore.vhd
--! @brief      
--! @author     Richard Haeussler
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
use ieee.std_logic_misc.all;
use work.NIST_LWAPI_pkg.all;
use work.design_pkg.all;
use work.xoodyak_constants.all;


entity CryptoCore is
    Port (
        clk             : in   STD_LOGIC;
        rst             : in   STD_LOGIC;
        --PreProcessor===============================================
        ----!key----------------------------------------------------
        key             : in   STD_LOGIC_VECTOR (CCSW     -1 downto 0);
        key_valid       : in   STD_LOGIC;
        key_ready       : out  STD_LOGIC;
        ----!Data----------------------------------------------------
        bdi             : in   STD_LOGIC_VECTOR (CCW     -1 downto 0);
        bdi_valid       : in   STD_LOGIC;
        bdi_ready       : out  STD_LOGIC;
        bdi_pad_loc     : in   STD_LOGIC_VECTOR (CCWdiv8 -1 downto 0);
        bdi_valid_bytes : in   STD_LOGIC_VECTOR (CCWdiv8 -1 downto 0);
        bdi_size        : in   STD_LOGIC_VECTOR (3       -1 downto 0);
        bdi_eot         : in   STD_LOGIC;
        bdi_eoi         : in   STD_LOGIC;
        bdi_type        : in   STD_LOGIC_VECTOR (4       -1 downto 0);
        decrypt_in      : in   STD_LOGIC;
        key_update      : in   STD_LOGIC;
        hash_in         : in   std_logic;
        --!Post Processor=========================================
        bdo             : out  STD_LOGIC_VECTOR (CCW      -1 downto 0);
        bdo_valid       : out  STD_LOGIC;
        bdo_ready       : in   STD_LOGIC;
        bdo_type        : out  STD_LOGIC_VECTOR (4       -1 downto 0);
        bdo_valid_bytes : out  STD_LOGIC_VECTOR (CCWdiv8 -1 downto 0);
        end_of_block    : out  STD_LOGIC;
        msg_auth_valid  : out  STD_LOGIC;
        msg_auth_ready  : in   STD_LOGIC;
        msg_auth        : out  STD_LOGIC
    );
end CryptoCore;

architecture behavioral of CryptoCore is
    --signals to data path components
    --cyc_ops inputs only
    signal cycd_sel: std_logic_vector(1 downto 0);
    signal extract_sel: std_logic;
    signal cyc_state_update_sel: std_logic;
    signal xor_sel: std_logic;
    signal cu_cd_s: std_logic_vector(7 downto 0);
    
    --state memory signals
    signal state_main_en: std_logic_vector(2 downto 0);
    signal state_main_sel: std_logic_vector(6 downto 0);
    signal key_en: std_logic;
      
    --perm_count
    signal rnd_counter: std_logic_vector(NUM_ROUNDS_BITS-1 downto 0);
    signal en_rnd: std_logic;
    signal load_rnd: std_logic;
    
    --data counter
    signal dcount: std_logic_vector(ADDRESS_ENTRIES_BITs-1 downto 0);
    signal dcount_int: integer;
    signal en_dcount: std_logic;
    signal load_dcount: std_logic;
    
    
    -- State signals
    type cycstate_t is (IDLE, STORE_KEY,
           CYC_DOWN, CYC_ADD_BYTE,
           CYC_UP_PERM, CYC_UP_EXTRACT);
    signal n_cyc_s, cyc_s: cycstate_t;
    
    type mess_states_t is (ABSORB_NONCE,  ABSORB_AD, ABSORB_MSG, SQUEEZE, SQUEEZE2, ABSORB_HASH, STORE_KEY);
    signal calling_state, n_calling_state: mess_states_t;
    
    type mode_t is (KEYED, HASH, HASH2);
    signal mode, n_mode: mode_t;
  
  
    --data signals
    signal bdi_key : std_logic_vector(CCW - 1 downto 0);
    signal decrypt_op_s, n_decrypt_op_s: std_logic;
    
    -- Output signals
    signal bdo_s                        : std_logic_vector(CCW - 1 downto 0);
    
    -- This signal is used to send header messages
    signal n_tag_verified, tag_verified :std_logic;
    
    signal bdi_eot_prev, n_bdi_eot_prev : std_logic;
    
    signal gtr_one_perm, n_gtr_one_perm: std_logic;

begin

  --round counter
  round_counter: entity work.counter
     generic map (num_bits =>NUM_ROUNDS_BITS)
     port map (
     clk => clk,
     reset => load_rnd,
     enable => en_rnd,
     q => rnd_counter
     );
  --data counter
    E_dcount: entity work.counter
     generic map (num_bits => 4)
     port map (
     clk => clk,
     reset => load_dcount,
     enable => en_dcount,
     q => dcount
     );
     
  cyc_ops: entity work.cyclist_ops
      generic map (DATA_LEN => 32)
    port map (
    clk => clk,
    key_en => key_en,
    state_main_en => state_main_en,
    state_main_sel => state_main_sel,
    cyc_state_update_sel => cyc_state_update_sel,
    xor_sel => xor_sel,
    cycd_sel => cycd_sel,
    extract_sel => extract_sel,
    bdi_key => bdi_key,
    cu_cd => cu_cd_s,
    dcount_in => dcount,
    rnd_counter => rnd_counter,
    bdo_out => bdo_s
    );
    
    --convert to integer for comparison 
    dcount_int <= to_integer(unsigned(dcount));

    --data outputs
    bdo                 <= bdo_s;
    
    test :process(clk)
    begin
        if bdi_type = HDR_MSG then
            extract_sel <= '1';
            bdo_type <= HDR_MSG;
        elsif bdi_type = HDR_CT then
            extract_sel <= '1';
            bdo_type <= HDR_CT;
        else
            bdo_type <= HDR_TAG;
            extract_sel <= '0';
        end if;
        if cyc_s = CYC_ADD_BYTE then
            xor_sel       <= '1';    --defaults to bdi_data
        else
            xor_sel       <= '0';    --defaults to bdi_data
        end if;
    end process;    
    top_level_states: process(cyc_s, calling_state,
                            decrypt_op_s, decrypt_in,
                            bdo_s, bdo_ready,
                            bdi_valid, clk,  bdi_valid_bytes, bdi_type, bdi_size, bdi_eot, bdi_eot_prev,
                            hash_in, gtr_one_perm,
                            dcount_int, rnd_counter,
                            mode,
                            key_update, key_valid,
                            msg_auth_ready,
                            tag_verified)
    begin
      n_calling_state     <= calling_state;
      n_cyc_s             <= cyc_s;
      n_mode              <= mode;
      
      --default values
      key_ready         <= '0';
      bdi_ready         <= '0';
      bdi_key           <= bdi;
      
      --state_ram_defaults
      state_main_sel      <= "0000000";    --defaults to perm_addr
      state_main_en       <= "000";
      key_en              <= '0';
      
      --cyc_ops_defaults
      cycd_sel      <= "00";
      cyc_state_update_sel<= '0';
      cu_cd_s         <= (others => '0');
      
      --Defaults for counters
      en_dcount <= '0';
      en_rnd    <= '0';
      load_dcount <= '0';
      load_rnd  <='0';
      
      --output variables
      bdo_valid <= '0';
      bdo_valid_bytes     <= bdi_valid_bytes;
      end_of_block <= '0';
      n_decrypt_op_s <= decrypt_op_s;
      
      msg_auth_valid <= '0';
      msg_auth <= '0';
      n_tag_verified <= '1';
      
      n_gtr_one_perm <= gtr_one_perm;
      n_bdi_eot_prev <= '0';


        
      
    case cyc_s is
    when IDLE =>
        n_tag_verified  <= '0';
        load_dcount <= '1';  --zero out the data counter
        n_gtr_one_perm <= '0';
        state_main_sel <= "0111111";
        state_main_en <= "111";
        if (key_valid = '1' or bdi_valid = '1') then
            if (hash_in = '1') then
                n_cyc_s <= CYC_DOWN;
                n_calling_state <= ABSORB_HASH;
                n_mode <= HASH;
                n_decrypt_op_s <= '0';
            else
                n_mode <= KEYED;
                if key_update = '1' then
                    n_cyc_s <= STORE_KEY;
                else
                    load_dcount <= '1';
                    state_main_sel <="0101010";
                    state_main_en <= "111";
                    n_cyc_s <= CYC_DOWN;
                    n_calling_state <= ABSORB_NONCE;
                end if;
            end if;
        end if;

    when STORE_KEY =>
        if key_valid = '1' then
            bdi_key <= key;
            key_ready <= '1';
            en_dcount <= '1';
            state_main_en <= "001";
        -- Writing the value of cd to the state
        elsif (dcount_int = KEY_WORDS) then
            bdi_key <= x"00010000"; --rotate internal to cyc
            state_main_en <= "110";
            load_dcount <= '1';
            cu_cd_s <= x"02";
            load_rnd <= '1';
            n_cyc_s <= CYC_UP_PERM;
            n_calling_state <= STORE_KEY; 
       end if;

    when CYC_DOWN =>
        n_bdi_eot_prev <= bdi_eot;
        if (calling_state = ABSORB_NONCE) then
            n_decrypt_op_s <= decrypt_in;
            if bdi_valid = '1' then
                if dcount_int = 3 then
                    n_cyc_s <= CYC_ADD_BYTE;
                end if;
                bdi_ready <= '1';
                state_main_en <= "001";
                en_dcount <= '1';
            end if;
        elsif bdi_valid_bytes = "0000" and bdi_eot = '1' then
            n_cyc_s <= CYC_ADD_BYTE;
        elsif calling_state = ABSORB_AD or calling_state = ABSORB_HASH then
            if bdi_type = HDR_AD or bdi_type = "0000"  or bdi_type = HDR_HASH_MSG then
                if bdi_valid = '1' then
                    if bdi_eot = '1' then
                        n_cyc_s <= CYC_ADD_BYTE;
                        if bdi_valid_bytes = x"F" then
                            bdi_ready <= '1';
                            en_dcount <= '1';
                            if dcount_int > 7 then
                                state_main_sel <= "1000000";
                                state_main_en <= "100";
                            elsif dcount_int > 3 then
                                state_main_en <= "010";
                            else
                                state_main_en <= "001";
                            end if;
                        end if;
                    else
                        if dcount_int = 10  and calling_state = ABSORB_AD then
                            n_cyc_s <= CYC_ADD_BYTE;
                        elsif dcount_int = 3 and calling_state = ABSORB_HASH then
                            n_cyc_s <= CYC_ADD_BYTE;
                        end if;
                        if dcount_int > 7 then
                            state_main_sel <= "1000000";
                            state_main_en <= "100";
                        elsif dcount_int > 3 then
                            state_main_en <= "010";
                        else
                            state_main_en <= "001";
                        end if;
                        bdi_ready <= '1';
                        en_dcount <= '1';
                    end if;
                elsif bdi_type = "0000" and bdi_valid_bytes = x"F" then
                    n_cyc_s <= CYC_ADD_BYTE;
                end if;
            else
                n_cyc_s <= CYC_ADD_BYTE;
            end if;
        else
            -- calling_state is ABSORB_MSG
            if bdi_type = HDR_CT then
                cyc_state_update_sel <= '1';
            end if;
            if (dcount_int = TAG_SIZE_CW - 1 ) then
                end_of_block <= '1';
            end if;
            if bdi_type = HDR_MSG or bdi_type = HDR_CT or bdi_type = "0000" then
                if bdi_valid = '1' and bdo_ready = '1' then
                    if bdi_eot = '1' then
                        n_cyc_s <= CYC_ADD_BYTE;
                        if bdi_size = "100" then
                            bdi_ready <= '1';
                            bdo_valid <= '1';
                            if dcount_int > 3 then
                                state_main_en <= "010";
                            else
                                state_main_en <= "001";
                            end if;
                            en_dcount <= '1';
                        end if;
                    else
                        if dcount_int = 5 then
                            n_cyc_s <= CYC_ADD_BYTE;
                        end if;
                        bdo_valid <= '1';
                        bdi_ready <= '1';
                        en_dcount <= '1';
                        if dcount_int > 3 then
                            state_main_en <= "010";
                        else
                            state_main_en <= "001";
                        end if;
                    end if;
                elsif bdi_type = "0000" and bdi_valid_bytes = x"F" then
                    n_cyc_s <= CYC_ADD_BYTE;
                end if;
            else
                n_cyc_s <= CYC_ADD_BYTE;
            end if;
        end if;
    when CYC_ADD_BYTE =>
        -- Possibly loading the next instruction of the same type
        if bdi_type = "0000" and bdi_eot_prev /= '1' and bdi_eot /= '1' and bdi_valid_bytes = "0000" then
            null;
        else
            en_dcount <= '1';
            load_dcount <= '1';
            load_rnd <= '1';
            n_cyc_s <= CYC_UP_PERM;
            if calling_state = ABSORB_NONCE then
                n_calling_state <= ABSORB_AD;
                cu_cd_s <= x"03";
                state_main_en <= "110";
            elsif calling_state = ABSORB_AD then
                if dcount_int > 7 then
                    state_main_en <= "100";
                    state_main_sel <= "1000000";
                elsif dcount_int > 3 then
                    state_main_en <= "110";
                else
                    state_main_en <= "101";
                end if;
                if bdi_type /= HDR_AD then
                    n_calling_state <= ABSORB_MSG;
                    n_gtr_one_perm <= '0';
                    if gtr_one_perm = '0' then
                        cu_cd_s <= x"83";
                    else
                        cu_cd_s <= x"80";
                    end if;
                elsif bdi_valid = '1' and bdi_size(1 downto 0) /= "00" and dcount_int < 11 then
                    bdi_ready <= '1';
                    cycd_sel <= bdi_size(1 downto 0);
                    if bdi_eot = '1' then
                        n_calling_state <= ABSORB_MSG;
                        n_gtr_one_perm <= '0';
                        if gtr_one_perm = '0' then
                            cu_cd_s <= x"83";
                        else
                            cu_cd_s <= x"80";
                        end if;
                    end if;
                elsif dcount_int = 11 then
                    n_gtr_one_perm <= '1';
                    if gtr_one_perm = '0' then
                        cu_cd_s <= x"03";
                    end if;
                end if;
            elsif calling_state = ABSORB_MSG then
                if bdi_type /= HDR_MSG and bdi_type /= HDR_CT then
                    n_calling_state <= SQUEEZE;
                    n_gtr_one_perm <= '0';
                    cu_cd_s <= x"40";
                    if dcount_int > 3 then
                        state_main_en <= "110";
                    else
                        state_main_en <= "101";
                    end if;
                elsif bdi_valid = '1' and bdo_ready = '1' and bdi_size(1 downto 0) /= "00" and dcount_int < 6 then
                    bdi_ready <= '1';
                    cycd_sel <= bdi_size(1 downto 0);
                    if bdi_type = HDR_MSG then
                        bdo_valid <= '1';
                        if (dcount_int = TAG_SIZE_CW - 1 ) then
                            end_of_block <= '1';
                        end if;
                    elsif bdi_type = HDR_CT then
                        cyc_state_update_sel <= '1';
                    end if;
                    if bdi_eot = '1' then
                        n_gtr_one_perm <= '0';
                        n_calling_state <= SQUEEZE;
                        cu_cd_s <= x"40";
                        if dcount_int > 3 then
                            state_main_en <= "110";
                        else
                            state_main_en <= "101";
                        end if;
                    else
                        if dcount_int > 3 then
                            state_main_en <= "010";
                        else
                            state_main_en <= "001";
                        end if;
                    end if;
                elsif dcount_int = 6 then
                    state_main_en <= "010";
                end if;
            elsif calling_state = ABSORB_HASH then
                if gtr_one_perm = '0' then
                    cu_cd_s <= x"01";
                    if dcount_int /= 4 then
                        state_main_en <= "101";
                    else
                        state_main_en <= "110";
                    end if;
                else
                    if dcount_int /= 4 then
                        state_main_en <= "001";
                    else
                        state_main_en <= "010";
                    end if;
                end if;
                if bdi_type = HDR_HASH_MSG then
                    if bdi_valid = '1'  and dcount_int /= 4 then
                        bdi_ready <= '1';
                        cycd_sel <= bdi_size(1 downto 0);
                        if bdi_eot = '1' then
                            n_calling_state <= SQUEEZE;
                        end if;
                    else
                        n_gtr_one_perm <= '1';
                    end if;
                else
                    n_calling_state <= SQUEEZE;
                end if;
            elsif calling_state = SQUEEZE2 then
                cu_cd_s <= x"01";
                state_main_en <= "001";
            end if; 
       end if; 

        
    when CYC_UP_PERM =>
        --In the permutation
        --Loop through for NUM_ROUNDS
        state_main_en <= "111";
        state_main_sel <= "0010101";
        n_tag_verified <= '1';
        en_rnd <='1';
        if (rnd_counter = "1011") then
            load_dcount <= '1';
            load_rnd <= '1';
            --Jump to CYC_DOWN_1 unless tag needs to be verified
            if calling_state = SQUEEZE or calling_state = SQUEEZE2 then
                n_cyc_s <= CYC_UP_EXTRACT;
            elsif (calling_state = STORE_KEY) then
                key_en <= '1';
                n_calling_state <=ABSORB_NONCE;
                n_cyc_s <= CYC_DOWN;
            else
                n_cyc_s <= CYC_DOWN;
            end if;
        end if;
        
    when CYC_UP_EXTRACT =>
        -- performing encryption extract the tag and send it
        if (decrypt_op_s /= '1') then
            bdo_valid <= '1';
            bdo_valid_bytes <= (others => '1');
            --Update counter if data if valid
            if (bdo_ready = '1') then
                en_dcount <= '1';
            end if;
            --Send end_of_block when TAG_SIZE_CW is reached
            if (dcount_int = TAG_SIZE_CW - 1 ) then
                if mode = HASH and calling_state /= SQUEEZE2 then
                    n_cyc_s <=  CYC_ADD_BYTE;
                    n_calling_state <=  SQUEEZE2;
                    load_dcount <= '1';
                else
                    end_of_block <= '1';
                    n_cyc_s <= IDLE;
                end if;
            end if;
        else
            --Verify the TAG if not set the tag to not verified
            if bdi_valid = '1' and msg_auth_ready = '1' then
                bdi_ready <= '1';
                en_dcount <= '1';
                if (dcount_int = TAG_SIZE_CW - 1) then
                    msg_auth_valid <= '1';
                    n_cyc_s <= IDLE;
                    --Final TAG word did not match
                    if (bdi /= bdo_s) then
                        msg_auth <= '0';
                    else
                        --The final tag matched and if there other tags matched
                        --this will be true otherwise false
                        msg_auth <= tag_verified;
                    end if;
                else
                    --Prior to the final tag update tag_verified to false if they
                    --do nto match
                    if (bdi /= bdo_s) then
                        n_tag_verified <= '0';
                    end if;
                end if;
            end if;
        end if;
    end case;
  end process;
  
GEN_p_reg_SYNC_RST: if (not ASYNC_RSTN) generate
    p_reg: process(clk)
    begin
        if rising_edge(clk) then
            if (rst = '1') then
                cyc_s               <= IDLE;
                mode                <= HASH;
                tag_verified        <= '0';
                calling_state       <= ABSORB_NONCE;
                gtr_one_perm        <= '0';
                decrypt_op_s        <= '0';
                bdi_eot_prev        <= '0';
            else
                cyc_s               <= n_cyc_s;
                mode                <= n_mode;
                tag_verified        <= n_tag_verified;
                calling_state       <= n_calling_state;
                gtr_one_perm        <= n_gtr_one_perm;
                decrypt_op_s        <= n_decrypt_op_s;
                bdi_eot_prev      <= n_bdi_eot_prev;
            end if;
        end if;
    end process p_reg;
end generate GEN_p_reg_SYNC_RST;
GEN_p_reg_ASYNC_RSTN: if (ASYNC_RSTN) generate
    p_reg: process(clk, rst)
    begin
        if (rst = '0') then
            cyc_s               <= IDLE;
            mode                <= HASH;
            tag_verified        <= '0';
            calling_state       <= ABSORB_NONCE;
            gtr_one_perm        <= '0';
            decrypt_op_s        <= '0';
            bdi_eot_prev        <= '0';
        elsif rising_edge(clk) then
            cyc_s               <= n_cyc_s;
            mode                <= n_mode;
            tag_verified        <= n_tag_verified;
            calling_state       <= n_calling_state;
            gtr_one_perm        <= n_gtr_one_perm;
            decrypt_op_s        <= n_decrypt_op_s;
            bdi_eot_prev      <= n_bdi_eot_prev;
        end if;
    end process p_reg;
end generate GEN_p_reg_ASYNC_RSTN;
end behavioral;

