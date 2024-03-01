import ctypes
import functools
import logging
import sys

from hook.cs.rpc import RpcServer
from hook.dll import Hook
from hook.process import Process


def get_server() -> RpcServer:
    return getattr(sys, "__inject_server__")


def ensure_same(args):
    if len(s := set(args)) != 1:
        raise ValueError(f"not same {args=}")
    return s.pop()


size_t_from = Process.current.read_ptr  # ctypes.c_size_t.from_address(a).value
i8_from = Process.current.read_i8  # lambda a: ctypes.c_int8.from_address(a).value
i32_from = Process.current.read_i32  # lambda a: ctypes.c_int32.from_address(a).value
u32_from = Process.current.read_u32  # lambda a: ctypes.c_uint32.from_address(a).value
u64_from = Process.current.read_u64  # lambda a: ctypes.c_uint64.from_address(a).value

v_func = lambda a, off: size_t_from(size_t_from(a) + off)


i_actor_0x50 = ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t)
i_actor_0x58 = ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t)


@functools.cache
def actor_base_name(a1):
    i_actor_0x50(v_func(a1, 0x50))(a1, ctypes.addressof(type_name := ctypes.c_char_p()))
    return type_name.value.decode()


@functools.cache
def actor_type_id(a1):
    i_actor_0x58(v_func(a1, 0x58))(a1, ctypes.addressof(val := ctypes.c_uint32()))
    return val.value


u32_from = Process.current.read_u32  # lambda a: ctypes.c_uint32.from_address(a).value


@functools.cache
def actor_idx(a1):
    return u32_from(a1 + 0x170)


class Act:
    _sys_key = "_act_"

    def __init__(self):
        self.server = get_server()
        scanner = Process.current.base_scanner()

        (p_process_damage_evt,) = scanner.find_val("e8 * * * * 66 83 bc 24 ? ? ? ? ?")
        self.process_damage_evt_hook = Hook(
            p_process_damage_evt,
            self._on_process_damage_evt,
            ctypes.c_size_t,
            [ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_uint8],
        )

        (p_process_dot_evt,) = ensure_same(
            map(tuple, scanner.find_vals("44 89 74 24 ? 48 ? ? ? ? 48 ? ? e8 * * * * 4c ? ? ? ? ? ?"))
        )
        self.process_dot_evt_hook = Hook(
            p_process_dot_evt, self._on_process_dot_evt, ctypes.c_size_t, [ctypes.c_size_t, ctypes.c_size_t]
        )

        (p_on_enter_area,) = scanner.find_val("e8 * * * * c5 ? ? ? c5 f8 29 45 ? c7 45 ? ? ? ? ?")
        self.on_enter_area_hook = Hook(
            p_on_enter_area, self._on_enter_area, ctypes.c_size_t, [ctypes.c_uint, ctypes.c_size_t, ctypes.c_uint8]
        )

        self.i_a1_0x40 = ctypes.CFUNCTYPE(
            ctypes.c_uint32, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t
        )

        (self.p_qword_1467572B0,) = scanner.find_val("48 ? ? * * * * 83 66 ? ? 48 ? ?")

        self.i_ui_comp_name = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_size_t)
        self.team_map = None

    def actor_data(self, a1):
        return actor_base_name(a1), actor_idx(a1), actor_type_id(a1), self.team_map.get(a1, -1) if self.team_map else -1

    def build_team_map(self):
        if self.team_map is not None:
            return
        res = {}
        qword_1467572B0 = size_t_from(self.p_qword_1467572B0)
        p_party_base = size_t_from(qword_1467572B0 + 0x20)
        p_party_tbl = size_t_from(p_party_base + 0x10 * (size_t_from(qword_1467572B0 + 0x38) & 0x6C4F1B4D) + 8)
        if p_party_tbl != size_t_from(qword_1467572B0 + 0x10) and (p_party_data := size_t_from(p_party_tbl + 0x30)):
            party_start = size_t_from(p_party_data + 0x18)
            party_end = size_t_from(p_party_data + 0x20)
            for i, p_data in enumerate(range(party_start, party_end, 0x10)):
                a1 = size_t_from(p_data + 8)
                if self.i_ui_comp_name(v_func(a1, 0x8))(a1) == b"ui::component::ControllerPlParameter01" and (
                    p_actor := size_t_from(a1 + 0x5D0)
                ):
                    p_actor_data = size_t_from(p_actor + 0x70)
                    res[p_actor_data] = i
                    print(f"[{i}] {p_actor=:#x}")
        self.team_map = res

    def _on_process_damage_evt(self, hook, a1, a2, a3, a4):
        source = target = 0
        try:
            self.build_team_map()
            target = size_t_from(size_t_from(a1 + 8))
            source = size_t_from(size_t_from(a2 + 0x18) + 0x70)
            flag = not (a4 or self.i_a1_0x40(v_func(a1, 0x40))(a1, a2, 0, target, source))
        except:
            logging.error("on_process_damage_evt", exc_info=True)
            flag = True
        res = hook.original(a1, a2, a3, a4)
        if flag:
            return res
        try:
            dmg = i32_from(a2 + 0xD0)
            flags_ = u64_from(a2 + 0xD8)
            if (1 << 7 | 1 << 50) & flags_:
                action_id = -1  # link attack
            elif (1 << 13 | 1 << 14) & flags_:
                action_id = -2  # limit break
            else:
                action_id = u32_from(a2 + 0x154)
            self._on_damage(source, target, dmg, flags_, action_id)
        except:
            logging.error("on_process_damage_evt", exc_info=True)
        return res

    def _on_process_dot_evt(self, hook, a1, a2):
        res = hook.original(a1, a2)
        try:
            dmg = i32_from(a2)
            target = size_t_from(size_t_from(a1 + 0x18) + 0x70)
            source = size_t_from(size_t_from(a1 + 0x30) + 0x70)
            self._on_damage(source, target, dmg, 0, -0x100)
        except:
            logging.error("on_process_dot_evt", exc_info=True)
        return res

    def _on_enter_area(self, hook, a1, a2, a3):
        res = hook.original(a1, a2, a3)
        try:
            self.team_map = None
            actor_base_name.cache_clear()
            actor_type_id.cache_clear()
            actor_idx.cache_clear()
            self.on_enter_area()
        except:
            logging.error("on_enter_area", exc_info=True)
        return res

    def _on_damage(self, source, target, damage, flags, action_id):
        # TODO: 找个通用方法溯源
        source_type_id = actor_type_id(source)
        if source_type_id == 0x2AF678E8:  # 菲莉宝宝 # Pl0700Ghost
            source = size_t_from(size_t_from(source + 0xE48) + 0x70)
        elif source_type_id == 0x8364C8BC:  # 菲莉 绕身球  # Pl0700GhostSatellite
            source = size_t_from(size_t_from(source + 0x508) + 0x70)
        elif source_type_id == 0xC9F45042:  # 老男人武器
            source = size_t_from(size_t_from(source + 0x578) + 0x70)
        elif source_type_id == 0xF5755C0E:  # 龙人化
            source = size_t_from(size_t_from(source + 0xD028) + 0x70)
        return self.on_damage(self.actor_data(source), self.actor_data(target), damage, flags, action_id)

    def on_damage(self, source, target, damage, flags, action_id):
        pass

    def on_enter_area(self):
        pass

    def install(self):
        assert not hasattr(sys, self._sys_key), "Act already installed"
        self.process_damage_evt_hook.install_and_enable()
        self.process_dot_evt_hook.install_and_enable()
        self.on_enter_area_hook.install_and_enable()
        setattr(sys, self._sys_key, self)
        return self

    def uninstall(self):
        assert getattr(sys, self._sys_key, None) is self, "Act not installed"
        self.process_damage_evt_hook.uninstall()
        self.process_dot_evt_hook.uninstall()
        self.on_enter_area_hook.uninstall()
        delattr(sys, self._sys_key)
        return self

    @classmethod
    def get_or_create(cls):
        if hasattr(sys, cls._sys_key):
            return getattr(sys, cls._sys_key)
        return cls().install()

    @classmethod
    def remove(cls):
        if hasattr(sys, cls._sys_key):
            getattr(sys, cls._sys_key).uninstall()

    @classmethod
    def reload(cls):
        cls.remove()
        return cls.get_or_create()
