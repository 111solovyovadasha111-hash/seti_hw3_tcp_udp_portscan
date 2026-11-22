import selectors


def make_selector():
    return selectors.EpollSelector()