if __name__ == "__main__":
    import env

    env.load_env(env.get_default_path())

    import core

    core.init()