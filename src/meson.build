# SPDX-License-Identifier: BSD-3-Clause
threading = dependency('threads', required: true)
wireshark = dependency('wireshark', required: true)

substrate = subproject(
	'substrate',
	default_options: [
		'build_tests=false',
		'default_library=static'
	],
).get_variable(
	'substrate_dep'
)

wiresharkVersion = wireshark.version()
wiresharkVersion = wiresharkVersion.split('.')

dissectorSrc = [
	'sol.cxx', 'frameReassembly.cxx', 'frameDissector.cxx', 'packetDissector.cxx'
]

dissector = shared_library(
	'sol',
	dissectorSrc,
	name_prefix: '',
	cpp_args: [
		'-DWS_BUILD_DLL',
		'-DHAVE_PLUGINS',
		'-DWIRESHARK_VERSION_MAJOR=@0@'.format(wiresharkVersion[0]),
		'-DWIRESHARK_VERSION_MINOR=@0@'.format(wiresharkVersion[1]),
		'-D_FORTIFY_SOURCE=2',
	],
	dependencies: [wireshark, substrate],
	gnu_symbol_visibility: 'inlineshidden',
	install: true,
	install_dir: wireshark.get_pkgconfig_variable('plugindir')
)
