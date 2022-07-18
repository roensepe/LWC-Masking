/*
 Designer: Mustafa Khairallah
 Nanyang Technological University
 Singapore
 Date: July, 2021
 */

// The DOM-Indep multiplier based sbox8 with registered
// shares. Takes 2 cycles. Non-pipelined, so the input
// must remain stable for 2 cycles, including the 
// refreshing mask r. Uses 4-way and 3-way multipliers.
module skinny_sbox8_dom1_rapid_non_pipelined (/*AUTOARG*/
   // Outputs
   bo1, bo0,
   // Inputs
   si0, si1, r, clk
   ) ;
   (*equivalent_register_removal = "no" *)output [7:0] bo1;
   (*equivalent_register_removal = "no" *)output [7:0] bo0;

   (*equivalent_register_removal = "no" *)input [7:0]  si0, si1;
   (*equivalent_register_removal = "no" *)input [24:0] r;
   (*equivalent_register_removal = "no" *)input        clk;

   wire [1:0]   bi7;
   wire [1:0]   bi6;
   wire [1:0]   bi5;
   wire [1:0]   bi4;
   wire [1:0]   bi3;
   wire [1:0]   bi2;
   wire [1:0]   bi1;
   wire [1:0]   bi0;
   
   wire [1:0] 	nbi7;
   wire [1:0]   nbi6;
   wire [1:0]   nbi5;
   wire [1:0]   nbi4;
   wire [1:0]   nbi3;
   wire [1:0]   nbi2;
   wire [1:0]   nbi1;
   wire [1:0]   nbi0;   

   wire [1:0]   a7;
   wire [1:0]   a6;
   wire [1:0]   a5;
   wire [1:0]   a4;
   wire [1:0]   a3;
   wire [1:0]   a2;
   wire [1:0]   a1;
   wire [1:0]   a0;

   wire [1:0]   na4;
   wire [1:0]   na3;
   wire [1:0]   na2;

   assign bi0 = {si1[0],si0[0]};
   assign bi1 = {si1[1],si0[1]};
   assign bi2 = {si1[2],si0[2]};
   assign bi3 = {si1[3],si0[3]};
   assign bi4 = {si1[4],si0[4]};
   assign bi5 = {si1[5],si0[5]};
   assign bi6 = {si1[6],si0[6]};
   assign bi7 = {si1[7],si0[7]};

   assign nbi0 = {si1[0],~si0[0]};
   assign nbi1 = {si1[1],~si0[1]};
   assign nbi2 = {si1[2],~si0[2]};
   assign nbi3 = {si1[3],~si0[3]};
   assign nbi4 = {si1[4],~si0[4]};
   assign nbi5 = {si1[5],~si0[5]};
   assign nbi6 = {si1[6],~si0[6]};
   assign nbi7 = {si1[7],~si0[7]};

   assign na4 = a4 ^ 2'b01;
   assign na3 = a3 ^ 2'b01;
   assign na2 = a2 ^ 2'b01;

   dom1_rpd_sbox8_cfn_fr b764 (a0,bi7,bi6,bi4,r[0],clk);
   dom1_rpd_sbox8_cfn_fr b320 (a1,bi3,bi2,bi0,r[1],clk);
   dom1_rpd_sbox8_cfn_fr b216 (a2,bi2,bi1,bi6,r[2],clk);
   rapid_a3 a3_cf (a3,nbi7,nbi6,bi5,nbi4,nbi3,nbi2,nbi0,r[16:3],clk);   
   rapid_a4 a4_cf (a4,nbi3,nbi2,bi1,nbi0,r[18:17],clk);
   
   dom1_rpd_sbox8_cfn_fr b237 (a5,a2, a3, bi7,r[19],clk);
   dom1_rpd_sbox8_cfn_fr b303 (a6,a3, a0, bi3,r[20],clk);
   rapid_a7 a7_cf (a7,nbi7,na4,na3,na2,bi2,r[24:21],clk);

   assign {bo1[6],bo0[6]} = a0;
   assign {bo1[5],bo0[5]} = a1;
   assign {bo1[2],bo0[2]} = a2;
   assign {bo1[7],bo0[7]} = a3;
   assign {bo1[3],bo0[3]} = a4;
   assign {bo1[1],bo0[1]} = a5;
   assign {bo1[4],bo0[4]} = a6;
   assign {bo1[0],bo0[0]} = a7;
endmodule // skinny_sbox8_dom1_rapid_non_pipelined


// The core registered function of the skinny sbox8.
// fr: fully registered, all and operations are
// registered.
// cfn: core function
// The core function is basically (x nor y) xor z
// We use de morgan's law to convert it to:
// ((~x) and (~y)) xor z and use the DOM-Indep
// multiplier for the and gate. We add the shares of
// z to the independent and gates and register the
// output of (a and b) xor c, while for the mixed
// shares we also use (a and b) xor c, but c is the
// fresh randomness.
module dom1_rpd_sbox8_cfn_fr (/*AUTOARG*/
   // Outputs
   f,
   // Inputs
   x, y, z, r, clk
   ) ;
   (*equivalent_register_removal = "no" *)output [1:0]        f;
   (*equivalent_register_removal = "no" *)input [1:0]         x, y, z;
   (*equivalent_register_removal = "no" *)input               r, clk;

   (*equivalent_register_removal = "no" *)reg [1:0]    g, t;
   always @ (posedge clk) begin
      g[1] <= (~x[1]) & (~y[1]) ^ z[1];
      g[0] <=   x[0]  &   y[0]  ^ z[0];
      
      t[1] <= ((~x[1]) &  y[0] ) ^ r;
      t[0] <= ((~y[1]) &  x[0] ) ^ r;
   end   

   assign f[0] = t[0] ^ g[0];
   assign f[1] = t[1] ^ g[1];
   
endmodule // dom1_sbox8_corefn_fullreg

module dom1_rpd_sbox8_cfn_fr_ne (/*AUTOARG*/
			         // Outputs
			         f,
			         // Inputs
			         x, y, z, r, clk
			      ) ;

   (*equivalent_register_removal = "no" *)output [1:0]        f;

   (*equivalent_register_removal = "no" *)input [1:0]         x, y, z;

   (*equivalent_register_removal = "no" *)input               r, clk;


   (*equivalent_register_removal = "no" *)reg [1:0]    g, t;

      always @ (negedge clk) begin
	 g[1] <= (~x[1]) & (~y[1]) ^ z[1];

	 g[0] <=   x[0]  &   y[0]  ^ z[0];


	 t[1] <= ((~x[1]) &  y[0] ) ^ r;

	 t[0] <= ((~y[1]) &  x[0] ) ^ r;

      end // always @ (posedge clk)

   assign f[0] = t[0] ^ g[0];

   assign f[1] = t[1] ^ g[1];


   endmodule // dom1_sbox8_corefn_fullreg

// Rapid calculation of a[3].
module rapid_a3 (/*AUTOARG*/
   // Outputs
   a3,
   // Inputs
   nb7, nb6, b5, nb4, nb3, nb2, nb0, r, clk
   ) ;
   (*equivalent_register_removal = "no" *)output [1:0] a3;
   (*equivalent_register_removal = "no" *)input [1:0] 	nb7, nb6, b5, nb4, nb3, nb2, nb0;
   (*equivalent_register_removal = "no" *)input [13:0] r;   
   (*equivalent_register_removal = "no" *)input 	clk;

   wire [1:0] 	t0;
   wire [1:0] 	t1;
   wire [1:0] 	t2;
   wire [1:0] 	t3;   

   (*equivalent_register_removal = "no" *)and4_dom1 g0 (t0,nb7,nb6,nb3,nb2,r[ 6: 0],clk);
   (*equivalent_register_removal = "no" *)and3_dom1 g1 (t1,nb7,nb6,nb0,    r[ 9: 7],clk);
   (*equivalent_register_removal = "no" *)and3_dom1 g2 (t2,nb4,nb3,nb2,    r[12:10],clk);
   (*equivalent_register_removal = "no" *)and2_dom1 g3 (t3,nb4,nb0,        r[13],   clk);
   
   assign a3 = t0 ^ t1 ^ t2 ^ t3 ^ b5;
   
endmodule // rapid_a3

// Rapid calculation of a[4].
module rapid_a4 (/*AUTOARG*/
   // Outputs
   a4,
   // Inputs
   nb3, nb2, b1, nb0, r, clk
   ) ;
   (*equivalent_register_removal = "no" *)output [1:0] a4;
   (*equivalent_register_removal = "no" *)input [1:0] 	nb3, nb2, b1, nb0;
   (*equivalent_register_removal = "no" *)input [1:0] 	r;   
   (*equivalent_register_removal = "no" *)input 	clk;

   (*equivalent_register_removal = "no" *)wire [1:0] 	t0;
   (*equivalent_register_removal = "no" *)wire [1:0] 	t1;

   (*equivalent_register_removal = "no" *)and2_dom1 g0 (t0,nb3,nb2,r[0],clk);
   (*equivalent_register_removal = "no" *)and2_dom1 g1 (t1,nb0,nb3,r[1],clk);
   
   assign a4 = t0 ^ t1 ^ b1;
   
endmodule // rapid_a4

// Rapid calculation of a[7].
module rapid_a7 (/*AUTOARG*/
   // Outputs
   a7,
   // Inputs
   nb7, na4, na3, na2, b2, r, clk
   ) ;
   (*equivalent_register_removal = "no" *)output [1:0] a7;
   (*equivalent_register_removal = "no" *)input [1:0] 	nb7, na4, na3, na2, b2;
   (*equivalent_register_removal = "no" *)input [3:0] r;   
   (*equivalent_register_removal = "no" *)input 	clk;

   wire [1:0] 	t0;
   wire [1:0] 	t1;

   (*equivalent_register_removal = "no" *)and3_dom1 g0 (t0,na2,na3,na4,r[2:0],clk);
   (*equivalent_register_removal = "no" *)and2_dom1 g1 (t1,nb7,na4,    r[3],  clk);
   
   assign a7 = t0 ^ t1 ^ b2;
   
endmodule // rapid_a7

// Domain-oriented 4-way AND gate (GF(2) multiplier).
module and4_dom1_ne (/*AUTOARG*/
		     // Outputs
		     z,
		     // Inputs
		     a, b, c, d, r, clk
		  ) ;

   (*equivalent_register_removal = "no" *)output [1:0]  z;

   (*equivalent_register_removal = "no" *)input [1:0]   a, b, c, d;

   (*equivalent_register_removal = "no" *)input [6:0]    r;

   (*equivalent_register_removal = "no" *)input         clk;


   (*equivalent_register_removal = "no" *)reg [15:0]    comp;

   always @ (negedge clk) begin
      comp[ 0] <= (a[0] & b[0] & c[0] & d[0]);
      
      comp[ 1] <= (a[0] & b[0] & c[0] & d[1]) ^ r[0];
      //
      comp[ 2] <= (a[0] & b[0] & c[1] & d[0]) ^ r[1];
      //
      comp[ 3] <= (a[0] & b[0] & c[1] & d[1]) ^ r[2];
      ///
      comp[ 4] <= (a[0] & b[1] & c[0] & d[0]) ^ r[3];
      //
      comp[ 5] <= (a[0] & b[1] & c[0] & d[1]) ^ r[4];
      ///
      comp[ 6] <= (a[0] & b[1] & c[1] & d[0]) ^ r[5];
      ///
      comp[ 7] <= (a[0] & b[1] & c[1] & d[1]) ^ r[6];
      //
      comp[ 8] <= (a[1] & b[0] & c[0] & d[0]) ^ r[6];
      //
      comp[ 9] <= (a[1] & b[0] & c[0] & d[1]) ^ r[5];
      ///
      comp[10] <= (a[1] & b[0] & c[1] & d[0]) ^ r[4];
      ///
      comp[11] <= (a[1] & b[0] & c[1] & d[1]) ^ r[3];
      //
      comp[12] <= (a[1] & b[1] & c[0] & d[0]) ^ r[2];
      ///
      comp[13] <= (a[1] & b[1] & c[0] & d[1]) ^ r[1];
      //
      comp[14] <= (a[1] & b[1] & c[1] & d[0]) ^ r[0];
      //
      comp[15] <= (a[1] & b[1] & c[1] & d[1]);
      
   end // always @ (posedge clk)
   
   assign z[0] = comp[ 0] ^ comp[ 1] ^ comp[ 2] ^ comp[ 3] ^
		 comp[ 4] ^ comp[ 5] ^ comp[ 6] ^ comp[ 7];

   assign z[1] = comp[ 8] ^ comp[ 9] ^ comp[10] ^ comp[11] ^
		 comp[12] ^ comp[13] ^ comp[14] ^ comp[15];


endmodule // and4_dom1_ne


   
module and4_dom1 (/*AUTOARG*/
   // Outputs
   z,
   // Inputs
   a, b, c, d, r, clk
   ) ;   
   (*equivalent_register_removal = "no" *)output [1:0]  z;
   (*equivalent_register_removal = "no" *)input [1:0]   a, b, c, d;
   (*equivalent_register_removal = "no" *)input [6:0] 	 r;
   (*equivalent_register_removal = "no" *)input         clk;

   (*equivalent_register_removal = "no" *)reg [15:0]    comp;

   always @ (posedge clk) begin
      comp[ 0] <= (a[0] & b[0] & c[0] & d[0]);
      comp[ 1] <= (a[0] & b[0] & c[0] & d[1]) ^ r[0];//
      comp[ 2] <= (a[0] & b[0] & c[1] & d[0]) ^ r[1];//
      comp[ 3] <= (a[0] & b[0] & c[1] & d[1]) ^ r[2];///
      comp[ 4] <= (a[0] & b[1] & c[0] & d[0]) ^ r[3];//
      comp[ 5] <= (a[0] & b[1] & c[0] & d[1]) ^ r[4];///
      comp[ 6] <= (a[0] & b[1] & c[1] & d[0]) ^ r[5];///
      comp[ 7] <= (a[0] & b[1] & c[1] & d[1]) ^ r[6];//
      comp[ 8] <= (a[1] & b[0] & c[0] & d[0]) ^ r[6];//
      comp[ 9] <= (a[1] & b[0] & c[0] & d[1]) ^ r[5];///
      comp[10] <= (a[1] & b[0] & c[1] & d[0]) ^ r[4];///
      comp[11] <= (a[1] & b[0] & c[1] & d[1]) ^ r[3];//
      comp[12] <= (a[1] & b[1] & c[0] & d[0]) ^ r[2];///
      comp[13] <= (a[1] & b[1] & c[0] & d[1]) ^ r[1];//
      comp[14] <= (a[1] & b[1] & c[1] & d[0]) ^ r[0];//
      comp[15] <= (a[1] & b[1] & c[1] & d[1]);
   end // always @ (posedge clk)
  
   assign z[0] = comp[ 0] ^ comp[ 1] ^ comp[ 2] ^ comp[ 3] ^ 
		 comp[ 4] ^ comp[ 5] ^ comp[ 6] ^ comp[ 7];
   assign z[1] = comp[ 8] ^ comp[ 9] ^ comp[10] ^ comp[11] ^ 
		 comp[12] ^ comp[13] ^ comp[14] ^ comp[15];
   
endmodule // and4_dom1

// Domain-oriented 3-way AND gate (GF(2) multiplier).
module and3_dom1 (/*AUTOARG*/
   // Outputs
   z,
   // Inputs
   a, b, c, r, clk
   ) ;   
   (*equivalent_register_removal = "no" *)output [1:0]  z;   
   (*equivalent_register_removal = "no" *)input [1:0]   a, b, c;
   (*equivalent_register_removal = "no" *)input [2:0] 	 r;
   (*equivalent_register_removal = "no" *)input         clk;

   (*equivalent_register_removal = "no" *)reg [7:0]    comp;

   always @ (posedge clk) begin
      comp[0] <= (a[0] & b[0] & c[0]);
      comp[1] <= (a[0] & b[0] & c[1]) ^ r[0];//
      comp[2] <= (a[0] & b[1] & c[0]) ^ r[1];//
      comp[3] <= (a[0] & b[1] & c[1]) ^ r[2];//
      comp[4] <= (a[1] & b[0] & c[0]) ^ r[2];//
      comp[5] <= (a[1] & b[0] & c[1]) ^ r[1];//
      comp[6] <= (a[1] & b[1] & c[0]) ^ r[0];//
      comp[7] <= (a[1] & b[1] & c[1]);
   end // always @ (posedge clk)
  
   assign z[0] = comp[0] ^ comp[1] ^ comp[2] ^ comp[3];   
   assign z[1] = comp[4] ^ comp[5] ^ comp[6] ^ comp[7];
   
endmodule // and3_dom1

module and3_dom1_ne (/*AUTOARG*/
		     // Outputs
		     z,
		     // Inputs
		     a, b, c, r, clk
		  ) ;

   (*equivalent_register_removal = "no" *)output [1:0]  z;

   (*equivalent_register_removal = "no" *)input [1:0]   a, b, c;

   (*equivalent_register_removal = "no" *)input [2:0]    r;

   (*equivalent_register_removal = "no" *)input         clk;


   (*equivalent_register_removal = "no" *)reg [7:0]    comp;


      always @ (negedge clk) begin
	 comp[0] <= (a[0] & b[0] & c[0]);

	 comp[1] <= (a[0] & b[0] & c[1]) ^ r[0];
	 //
	 comp[2] <= (a[0] & b[1] & c[0]) ^ r[1];
	 //
	 comp[3] <= (a[0] & b[1] & c[1]) ^ r[2];
	 //
	 comp[4] <= (a[1] & b[0] & c[0]) ^ r[2];
	 //
	 comp[5] <= (a[1] & b[0] & c[1]) ^ r[1];
	 //
	 comp[6] <= (a[1] & b[1] & c[0]) ^ r[0];
	 //
	 comp[7] <= (a[1] & b[1] & c[1]);

	    end // always @ (posedge clk)

   assign z[0] = comp[0] ^ comp[1] ^ comp[2] ^ comp[3];

   assign z[1] = comp[4] ^ comp[5] ^ comp[6] ^ comp[7];


endmodule // and3_dom1   

// Domain-oriented 2-way AND gate (GF(2) multiplier).
module and2_dom1 (/*AUTOARG*/
   // Outputs
   z,
   // Inputs
   a, b, r, clk
   ) ;   
   (*equivalent_register_removal = "no" *)output [1:0]  z;
   (*equivalent_register_removal = "no" *)input [1:0]   a, b;
   (*equivalent_register_removal = "no" *)input 	 r;
   (*equivalent_register_removal = "no" *)input         clk;

   (*equivalent_register_removal = "no" *)reg [3:0]    comp;

   always @ (posedge clk) begin
      comp[0] <= (a[0] & b[0]);
      comp[1] <= (a[0] & b[1]) ^ r;//
      comp[2] <= (a[1] & b[0]) ^ r;//
      comp[3] <= (a[1] & b[1]);
   end // always @ (posedge clk)
  
   assign z[0] = comp[0] ^ comp[1]; 
   assign z[1] = comp[2] ^ comp[3];
   
endmodule // and2_dom1

module and2_dom1_ne (/*AUTOARG*/
		     // Outputs
		     z,
		     // Inputs
		     a, b, r, clk
		  ) ;

   (*equivalent_register_removal = "no" *)output [1:0]  z;

   (*equivalent_register_removal = "no" *)input [1:0]   a, b;

   (*equivalent_register_removal = "no" *)input          r;

   (*equivalent_register_removal = "no" *)input         clk;


   (*equivalent_register_removal = "no" *)reg [3:0]    comp;


      always @ (negedge clk) begin
	 comp[0] <= (a[0] & b[0]);

	 comp[1] <= (a[0] & b[1]) ^ r;
	 //
	 comp[2] <= (a[1] & b[0]) ^ r;
	 //
	 comp[3] <= (a[1] & b[1]);

	    end // always @ (posedge clk)

   assign z[0] = comp[0] ^ comp[1];

   assign z[1] = comp[2] ^ comp[3];


   endmodule // and2_dom1
