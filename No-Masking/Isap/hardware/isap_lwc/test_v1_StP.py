#! /usr/bin/env python3
from pathlib import Path
import re
import subprocess
import sys

script_dir = Path(__file__).parent.resolve()

try:
    import cryptotvgen
    from cryptotvgen import cli
except ImportError as e:
    print('cryptotvgen is not installed!')
    print('Please go to `$(LWC_ROOT)/software/cryptotvgen` directory and run `pip install .` or `pip install -e .` and then try running the script again.')
    raise e


# TODO use pytest?

# SETTINGS
# TODO add argeparse for settings?
core_src_path = script_dir
lwc_root = script_dir.parents[1]
make_cmd = 'make'

print(f'script_dir={script_dir}')

variant = 'v1_StP'

variant_src_rtl = core_src_path / 'src_rtl' / variant
sources_list = variant_src_rtl / 'source_list.txt'
tb_sources_list = core_src_path / 'src_tb' / variant / 'source_list.txt'

variables = {'LWCSRC_DIR': str(lwc_root / 'hardware' / 'isap_lwc')}
# END OF SETTINGS

cnd_dir = lwc_root / 'software' / 'isap_ref'


def build_libs():
    args = [
        '--prepare_libs',
        '--candidates_dir', str(cnd_dir)
    ]
    return cli.run_cryptotvgen(args)


gen_tv_subfolder = Path('generated_tv').resolve()
gen_configs_subfolder = Path('generated_config').resolve()
gen_configs_subfolder.mkdir(exist_ok=True)


def gen_tv(ccw, blocks_per_segment, dest_dir):
    args = [
        '--lib_path', str(cnd_dir / 'lib'),
        '--aead', 'isapa128av20',
        '--hash', 'asconhashv12',
        '--io', str(ccw), str(ccw),
        '--key_size', '128',
        '--npub_size', '128',
        '--nsec_size', '0',
        '--message_digest_size', '256',
        '--tag_size', '128',
        '--block_size',    '64',
        '--block_size_ad', '64',
        '--dest', str(dest_dir),
        '--max_ad', '80',
        '--max_d', '80',
        '--max_io_per_line', '8',
        '--verify_lib',
    ]

    if blocks_per_segment:
        args += ['--max_block_per_sgmt', str(blocks_per_segment)]

    # ========================================================================
    # Message format
    # This format is only correct for encryption. We swap the ad/ct order
    # manually in a post processing step down below
    msg_format = '--msg_format npub data ad tag'.split()
    gen_test_routine = '--gen_test_routine 1 22 0'.split()
    gen_test_hash = '--gen_hash 1 22 0'.split()
    gen_test_combined = '--gen_test_combined 1 22 0'.split()

    # ========================================================================
    # Add option arguments together
    args += msg_format
    args += gen_test_routine
    args += gen_test_hash
    args += gen_test_combined

    return cli.run_cryptotvgen(args)


def get_lang(file: str):
    for ext in ['vhd', 'vhdl']:
        if file.endswith('.' + ext):
            return 'vhdl'
    if file.endswith('.v'):
        return 'verilog'
    if file.endswith('.sv'):
        return 'system-verilog'

def test_all():
    vhdl_files = []
    verilog_files = []
    with open(sources_list, 'r') as f:
        prj = {}
        prj['files'] = []
        data = f.read()
        for var, subst in variables.items():
            data = re.sub(r'\$\(' + var + r'\)', subst, data)

        for file in data.splitlines():
            if not Path(file).is_absolute():
                file = str(Path(variant_src_rtl) / file)
            if get_lang(file) == 'vhdl':
                vhdl_files.append(file)
            if get_lang(file) == 'verilog':
                verilog_files.append(file)
    # print(f'VHDL_FILES={vhdl_files}')

    orig_design_pkg = None
    orig_lwapi_pkg = None

    for f in vhdl_files:
        f_path = Path(f).resolve()
        if f_path.name.lower() == 'design_pkg.vhd':
            orig_design_pkg = f_path
        if f_path.name.lower() == 'nist_lwapi_pkg.vhd':
            orig_lwapi_pkg = f_path

    if not orig_design_pkg:
        sys.exit(f"'design_pkg.vhd' not found in VHDL files of sources.list!")
    if not orig_lwapi_pkg:
        sys.exit(f"'NIST_LWAPI_pkg.vhd' not found in VHDL files of sources.list!")

    #param_variants = [(32, 32), (32, 16), (32, 8), (16, 16), (8, 8)]
    param_variants = [(32, 32)] # TODO

    orig_config_ini = (core_src_path / 'config.ini').resolve()

    def gen_from_template(orig_filename, gen_filename, changes):
        with open(orig_filename, 'r') as orig:
            content = orig.read()
            for old, repl in changes:
                content = re.sub(old, repl, content)
        with open(gen_filename, 'w') as gen:
            gen.write(content)

    # TODO run other targets as well
    make_goal = 'sim-ghdl'

    results_dir = Path('testall_results').resolve()
    results_dir.mkdir(exist_ok=True)
    logs_dir = Path('testall_logs').resolve()
    logs_dir.mkdir(exist_ok=True)

    generated_sources = (core_src_path / 'generated_srcs')
    generated_sources.mkdir(exist_ok=True)

    tb_files = [ str((core_src_path / 'src_tb' / variant / s).resolve()) for s in ['LWC_TB_compatibility_pkg.vhd', 'LWC_TB.vhd'] ]

    for vhdl_std in ['93']:
        for ms in [False]:
            replace_files_map = {}
            for w, ccw in param_variants:

                for async_rstn in [False]:
                    replaced_lwapi_pkg = (
                        generated_sources / f'NIST_LWAPI_pkg_W{w}{"_ASYNC_RSTN" if async_rstn else ""}.vhd').resolve()
                    lwapi_pkg_changes = [
                        (r'(constant\s+W\s*:\s*integer\s*:=\s*)\d+(\s*;)', f'\\g<1>{w}\\g<2>'),
                        (r'(constant\s+ASYNC_RSTN\s*:\s+boolean\s*:=\s*)\w+(\s*;)', f'\\g<1>{async_rstn}\\g<2>')
                    ]
                    gen_from_template(orig_lwapi_pkg, replaced_lwapi_pkg, lwapi_pkg_changes)
                    replace_files_map[orig_lwapi_pkg] = replaced_lwapi_pkg

                    print(f'\n\n{"="*12}- Testing vhdl_std={vhdl_std} ms={ms} w={w} ccw={ccw} async_rstn={async_rstn} -{"="*12}\n')
                    gen_tv_dir = gen_tv_subfolder / f'TV{"_MS" if ms else ""}_{w}'
                    gen_tv(w, 2 if ms else None, gen_tv_dir)
                    
                    cmd = ['python3', 'fix_tv.py', 'generated_tv/TV_' + str(ccw)]
                    subprocess.Popen(cmd).wait()

                    replaced_design_pkg = (
                        generated_sources / f'design_pkg_{ccw}.vhd').resolve()
                    design_pkg_changes = [
                        (r'(constant\s+variant\s*:\s*set_selector\s*:=\s*ascon_lwc_)\d+(\s*;)', f'\\g<1>{ccw}\\g<2>')
                    ]
                    gen_from_template(orig_design_pkg, replaced_design_pkg, design_pkg_changes)
                    replace_files_map[orig_design_pkg] = replaced_design_pkg

                    # TODO alternatively, parse config.ini and generate anew
                    generated_config_ini = gen_configs_subfolder / \
                        f"config_{w}{'_MS' if ms else ''}_vhdl{vhdl_std}.ini"
                    config_ini_changes = [
                        (r'(G_FNAME_PDI\s*=\s*).*', f'\\g<1>"{gen_tv_dir}/pdi.txt"'),
                        (r'(G_FNAME_SDI\s*=\s*).*', f'\\g<1>"{gen_tv_dir}/sdi.txt"'),
                        (r'(G_FNAME_DO\s*=\s*).*', f'\\g<1>"{gen_tv_dir}/do.txt"'),
                        (r'(G_FNAME_LOG\s*=\s*).*',
                         f'\\g<1>\"{logs_dir}/log_W{w}_CCW{ccw}{"_ASYNCRSTN" if async_rstn else ""}{"_MS" if ms else ""}_VHDL{vhdl_std}.txt\"'),
                        (r'(G_FNAME_RESULT\s*=\s*).*',
                         f'\\g<1>\"{results_dir}/result_W{w}_CCW{ccw}{"_ASYNCRSTN" if async_rstn else ""}{"_MS" if ms else ""}_VHDL{vhdl_std}.txt\"'),
                        (r'(VHDL_STD\s*=\s*).*', f'\\g<1>{vhdl_std}'),
                    ]
                    gen_from_template(orig_config_ini, generated_config_ini, config_ini_changes)

                    def replace_file(f):
                        for orig in replace_files_map.keys():
                            if Path(f).resolve().samefile(orig):
                                return replace_files_map[orig]
                        return f

                    cfg_vhdl_files = [str(replace_file(f)) for f in vhdl_files]

                    cmd = [make_cmd, make_goal,
                           f"VHDL_FILES={' '.join(cfg_vhdl_files + tb_files)}",
                           f"VERILOG_FILES={' '.join(verilog_files)}",
                           f"CONFIG_LOC={generated_config_ini}",
                           "REBUILD=1"
                           ]
                    print(f'running `{" ".join(cmd)}` in {core_src_path}')
                    cp = subprocess.run(cmd, cwd=core_src_path)
                    cp.check_returncode()
                    cp = subprocess.run([make_cmd, 'clean-ghdl', f"SOURCES_LIST={sources_list}"], cwd=core_src_path)


if __name__ == "__main__":
    build_libs()
    test_all()
