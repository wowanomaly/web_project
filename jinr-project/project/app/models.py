from sqlalchemy import Column, BigInteger, Integer, String, Boolean, DateTime, Index, Text
from .db import Base

class Hit(Base):
    __tablename__ = "hits"

    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    ip         = Column(String(45), nullable=False, index=True)
    ts         = Column(DateTime(timezone=True), nullable=False, index=True)
    method     = Column(String(32))
    path       = Column(Text)
    status     = Column(Integer, index=True)
    size       = Column(Integer)
    referer    = Column(Text)
    ua         = Column(Text)

    is_attacker  = Column(Boolean, default=False, index=True)
    attack_kind  = Column(String(32), index=True)   # yisouspider | event_fuzz | curl_hammer | bingbot_flood

    country      = Column(String(64))
    city         = Column(String(128))

    __table_args__ = (
        Index("ix_hits_attacker_ts", "is_attacker", "ts"),
    )
