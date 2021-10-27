from .windows_builds import WindowsBuilds

class BuildMapper():
    @classmethod
    def map_windows_build(cls, build, is_workstation=None):
        build_dictionary = cls.__get_dictionary_from_role(is_workstation)

        return cls.__get_from_dictionary(build, build_dictionary)

    @staticmethod
    def __get_dictionary_from_role(is_workstation):
        if is_workstation is None:
            return WindowsBuilds.ambiguous_builds
        elif is_workstation:
            return WindowsBuilds.workstation_builds
        else:
            return WindowsBuilds.server_builds

    @staticmethod
    def __get_from_dictionary(build, build_dictionary):
        if build in build_dictionary:
            return build_dictionary[build]
        else:
            return None


